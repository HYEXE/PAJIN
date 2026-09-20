"""Process-local one-shot binding for governed specialist dispatch.

The serializable binding in this module is an audit description, not a bearer
capability.  Only a registry-minted opaque handle, held by the exact
``asyncio.Task`` that bound the C3B2 started authority, can advance the local
``available -> consumed -> retired`` lifecycle.  This slice performs no
Gateway, Worker, browser, network, or Target I/O.
"""

from __future__ import annotations

import asyncio
import threading
from _thread import RLock as RLockType
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Never, Self, SupportsIndex, cast

from pydantic import ConfigDict, Field, ValidationInfo, field_validator, model_validator

from pajin.agentic.durable import (
    AgenticCoordinationBinding,
    AgenticCoordinationStore,
    AgenticSpecialistCapabilityGrantConsumptionReceipt,
    AgenticSpecialistDispatchPlanEntry,
    AgenticSpecialistDispatchPlanState,
    AgenticSpecialistExecutionEntry,
    AgenticSpecialistExecutionState,
    VerifiedPlannedSpecialistDispatchStarted,
    _AgenticSpecialistDispatchRuntimeCapsule,
    _LinuxPinnedCoordinationDatabase,
)
from pajin.agentic.models import (
    AgenticStrictModel,
    Identifier,
    PentestSpecialization,
    Sha256,
    _literal_false,
)
from pajin.agentic.specialist_preparation import AgenticSpecialistPreparation
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.graph.approval import ActionApprovalConsumptionReceipt
from pajin.graph.authority import ActionPermit
from pajin.web_assessment.specialist_executors import (
    SpecialistExecutorDescriptor,
    WebSpecialistExecutorError,
    production_web_specialist_executor_catalog,
)
from pajin.web_assessment.specialist_profiles import (
    production_web_specialist_execution_profile_catalog,
)

AGENTIC_SPECIALIST_DISPATCH_BINDING_API_VERSION: Literal[
    "pajin.dev/agentic-specialist-dispatch-binding/v1alpha1"
] = "pajin.dev/agentic-specialist-dispatch-binding/v1alpha1"

_STORE_ID_PATTERN = r"^agentic-store:[a-f0-9]{32}$"
_BINDING_ID_PATTERN = r"^agentic-specialist-dispatch-binding_[a-f0-9]{64}$"
_PLAN_ID_PATTERN = r"^agentic-specialist-plan_[a-f0-9]{64}$"
_RESERVATION_ID_PATTERN = r"^agentic-specialist-reservation_[a-f0-9]{64}$"
_COMMAND_ID_PATTERN = r"^agent-command_[a-f0-9]{64}$"
_PREPARATION_ID_PATTERN = r"^agentic-specialist-preparation_[a-f0-9]{64}$"
_GRANT_RECEIPT_ID_PATTERN = r"^agentic-specialist-grant-consumption_[a-f0-9]{64}$"
_PERMIT_ID_PATTERN = r"^action-permit_[a-f0-9]{64}$"
_APPROVAL_RECEIPT_ID_PATTERN = r"^action-approval-receipt_[a-f0-9]{64}$"
_MAX_BINDING_BYTES = 64 * 1024
_STARTED_HANDLE_TRANSFER = AgenticCoordinationStore._transfer_planned_specialist_dispatch_started
_STORE_BINDING_OPERATION = AgenticCoordinationStore._specialist_dispatch_binding_operation
_STORE_RUNTIME_CLAIM = AgenticCoordinationStore._claim_transferred_specialist_dispatch_runtime
_STORE_REGISTRY_REGISTER = AgenticCoordinationStore._register_specialist_dispatch_binding_registry


class AgenticSpecialistDispatchBindingError(RuntimeError):
    """Raised when the C3C one-shot binding cannot remain exact."""


class AgenticSpecialistDispatchBindingState(StrEnum):
    """Closed process-local lifecycle for one specialist binding."""

    AVAILABLE = "available"
    CONSUMED = "consumed"
    RETIRED = "retired"


class AgenticSpecialistDispatchBinding(AgenticStrictModel):
    """Content-addressed C3B2-to-C3C identity tuple with no bearer authority."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/agentic-specialist-dispatch-binding/v1alpha1"] = Field(
        default=AGENTIC_SPECIALIST_DISPATCH_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AgenticSpecialistDispatchBinding"] = "AgenticSpecialistDispatchBinding"
    binding_id: str = Field(default="", alias="bindingId", pattern=_BINDING_ID_PATTERN)
    binding_digest: str = Field(
        default="",
        alias="bindingDigest",
        max_length=64,
    )

    store_id: str = Field(alias="storeId", pattern=_STORE_ID_PATTERN)
    coordination_binding_id: str = Field(
        alias="coordinationBindingId",
        pattern=r"^agentic-binding_[a-f0-9]{64}$",
    )
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    control_plane_run_id: Identifier = Field(alias="controlPlaneRunId")
    deployment_digest: Sha256 = Field(alias="deploymentDigest")
    campaign_id: str = Field(alias="campaignId", min_length=3, max_length=80)
    campaign_manifest_digest: Sha256 = Field(alias="campaignManifestDigest")

    plan_id: str = Field(alias="planId", pattern=_PLAN_ID_PATTERN)
    plan_digest: Sha256 = Field(alias="planDigest")
    plan_state_digest: Sha256 = Field(alias="planStateDigest")
    reservation_id: str = Field(alias="reservationId", pattern=_RESERVATION_ID_PATTERN)
    reservation_digest: Sha256 = Field(alias="reservationDigest")
    reservation_state_digest: Sha256 = Field(alias="reservationStateDigest")
    reservation_source_state_digest: Sha256 = Field(alias="reservationSourceStateDigest")
    command_id: str = Field(alias="commandId", pattern=_COMMAND_ID_PATTERN)
    command_digest: Sha256 = Field(alias="commandDigest")
    preparation_id: str = Field(alias="preparationId", pattern=_PREPARATION_ID_PATTERN)
    preparation_digest: Sha256 = Field(alias="preparationDigest")
    prepared_action_digest: Sha256 = Field(alias="preparedActionDigest")

    profile_registry_digest: Sha256 = Field(alias="profileRegistryDigest")
    profile_id: Identifier = Field(alias="profileId")
    profile_version: str = Field(alias="profileVersion", min_length=1, max_length=40)
    profile_digest: Sha256 = Field(alias="profileDigest")
    executor_catalog_digest: Sha256 = Field(alias="executorCatalogDigest")
    executor_id: Identifier = Field(alias="executorId")
    executor_version: str = Field(alias="executorVersion", min_length=1, max_length=40)
    executor_digest: Sha256 = Field(alias="executorDigest")

    activation_set_digest: Sha256 = Field(alias="activationSetDigest")
    release_id: str = Field(alias="releaseId", min_length=1, max_length=100)
    release_digest: Sha256 = Field(alias="releaseDigest")
    capability_id: Identifier = Field(alias="capabilityId")
    capability_version: str = Field(alias="capabilityVersion", min_length=1, max_length=40)
    capability_definition_digest: Sha256 = Field(alias="capabilityDefinitionDigest")
    capability_digest: Sha256 = Field(alias="capabilityDigest")
    tool_id: Identifier = Field(alias="toolId")
    tool_version: str = Field(alias="toolVersion", min_length=1, max_length=40)
    tool_digest: Sha256 = Field(alias="toolDigest")
    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    request_digest: Sha256 = Field(alias="requestDigest")

    capability_grant_id: str = Field(
        alias="capabilityGrantId",
        min_length=1,
        max_length=200,
    )
    capability_grant_digest: Sha256 = Field(alias="capabilityGrantDigest")
    grant_consumption_receipt_id: str = Field(
        alias="grantConsumptionReceiptId",
        pattern=_GRANT_RECEIPT_ID_PATTERN,
    )
    grant_consumption_receipt_digest: Sha256 = Field(alias="grantConsumptionReceiptDigest")
    action_permit_id: str = Field(alias="actionPermitId", pattern=_PERMIT_ID_PATTERN)
    action_permit_digest: Sha256 = Field(alias="actionPermitDigest")
    approval_id: str = Field(alias="approvalId", min_length=1, max_length=120)
    approval_digest: Sha256 = Field(alias="approvalDigest")
    approval_consumption_receipt_id: str = Field(
        alias="approvalConsumptionReceiptId",
        pattern=_APPROVAL_RECEIPT_ID_PATTERN,
    )
    approval_consumption_receipt_digest: Sha256 = Field(alias="approvalConsumptionReceiptDigest")
    dispatch_id: str = Field(
        alias="dispatchId",
        pattern=r"^action-dispatch_[a-f0-9]{64}$",
    )

    target_agent_id: Identifier = Field(alias="targetAgentId")
    task_id: Identifier = Field(alias="taskId")
    target_id: Identifier = Field(alias="targetId")
    target_digest: Sha256 = Field(alias="targetDigest")
    specialization: PentestSpecialization

    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_authority: Literal[False] = Field(default=False, alias="permitAuthority")
    grant_authority: Literal[False] = Field(default=False, alias="grantAuthority")
    capability_authority: Literal[False] = Field(
        default=False,
        alias="capabilityAuthority",
    )
    gateway_authority: Literal[False] = Field(default=False, alias="gatewayAuthority")
    worker_authority: Literal[False] = Field(default=False, alias="workerAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    evidence_authority: Literal[False] = Field(default=False, alias="evidenceAuthority")
    independent_validation_performed: Literal[False] = Field(
        default=False,
        alias="independentValidationPerformed",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_authority: Literal[False] = Field(default=False, alias="graphAuthority")
    report_authority: Literal[False] = Field(default=False, alias="reportAuthority")
    sarif_authority: Literal[False] = Field(default=False, alias="sarifAuthority")
    poc_authority: Literal[False] = Field(default=False, alias="pocAuthority")
    caller_authored_routes_allowed: Literal[False] = Field(
        default=False,
        alias="callerAuthoredRoutesAllowed",
    )
    caller_authored_payloads_allowed: Literal[False] = Field(
        default=False,
        alias="callerAuthoredPayloadsAllowed",
    )
    caller_authored_policies_allowed: Literal[False] = Field(
        default=False,
        alias="callerAuthoredPoliciesAllowed",
    )
    caller_authored_transport_allowed: Literal[False] = Field(
        default=False,
        alias="callerAuthoredTransportAllowed",
    )
    serialized_bearer_authority: Literal[False] = Field(
        default=False,
        alias="serializedBearerAuthority",
    )
    target_io_performed: Literal[False] = Field(default=False, alias="targetIoPerformed")

    @field_validator(
        "automatic_redispatch_authorized",
        "approval_authority",
        "permit_authority",
        "grant_authority",
        "capability_authority",
        "gateway_authority",
        "worker_authority",
        "execution_authority",
        "evidence_authority",
        "independent_validation_performed",
        "finding_authority",
        "graph_authority",
        "report_authority",
        "sarif_authority",
        "poc_authority",
        "caller_authored_routes_allowed",
        "caller_authored_payloads_allowed",
        "caller_authored_policies_allowed",
        "caller_authored_transport_allowed",
        "serialized_bearer_authority",
        "target_io_performed",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = discovery_digest(
            "pajin.agentic.specialist-dispatch-binding/v1",
            material,
        )
        expected_id = f"agentic-specialist-dispatch-binding_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("specialist dispatch Binding Digest differs")
        if self.binding_id and self.binding_id != expected_id:
            raise ValueError("specialist dispatch Binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist dispatch binding",
            max_bytes=_MAX_BINDING_BYTES,
        )
        return self


class _UncopyableProcessAuthority:
    """Shared local-only protection for registry and handle objects."""

    __slots__ = ()

    def __copy__(self) -> Never:
        raise TypeError("specialist dispatch process authority cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("specialist dispatch process authority cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("specialist dispatch process authority cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("specialist dispatch process authority cannot be serialized")

    def __getstate__(self) -> Never:
        raise TypeError("specialist dispatch process authority cannot be serialized")


@dataclass(frozen=True, slots=True)
class _BindingRegistryEntry:
    handle: VerifiedAgenticSpecialistDispatchBinding
    binding: AgenticSpecialistDispatchBinding
    owner_task: asyncio.Task[object]
    token: object
    runtime: _AgenticSpecialistDispatchRuntimeCapsule
    binding_id: str
    binding_digest: str
    identities: tuple[tuple[str, str], ...]


class VerifiedAgenticSpecialistDispatchBinding(_UncopyableProcessAuthority):
    """Opaque task-local handle for one registry-owned binding lifecycle."""

    __slots__ = (
        "__binding_digest",
        "__binding_id",
        "__identities",
        "__registry",
        "__runtime_token",
        "__task",
        "__token",
    )
    __binding_digest: str
    __binding_id: str
    __identities: tuple[tuple[str, str], ...]
    __registry: AgenticSpecialistDispatchBindingRegistry
    __runtime_token: object
    __task: asyncio.Task[object]
    __token: object

    def __init_subclass__(cls) -> Never:
        raise TypeError("verified specialist dispatch binding handles cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("verified specialist dispatch binding handles are immutable")

    def __delattr__(self, _name: str) -> Never:
        raise AttributeError("verified specialist dispatch binding handles are immutable")

    def __init__(
        self,
        *,
        binding_id: str,
        binding_digest: str,
        identities: tuple[tuple[str, str], ...],
        registry: AgenticSpecialistDispatchBindingRegistry,
        runtime_token: object,
        task: asyncio.Task[object],
        token: object,
    ) -> None:
        prefix = "_VerifiedAgenticSpecialistDispatchBinding__"
        object.__setattr__(self, prefix + "binding_id", binding_id)
        object.__setattr__(self, prefix + "binding_digest", binding_digest)
        object.__setattr__(self, prefix + "identities", identities)
        object.__setattr__(self, prefix + "registry", registry)
        object.__setattr__(self, prefix + "runtime_token", runtime_token)
        object.__setattr__(self, prefix + "task", task)
        object.__setattr__(self, prefix + "token", token)

    @property
    def binding(self) -> AgenticSpecialistDispatchBinding:
        """Return a detached audit value; it is never accepted as registry authority."""

        return self.__registry.describe(self)

    @property
    def binding_id(self) -> str:
        return self.__binding_id

    def consume(self) -> VerifiedAgenticSpecialistDispatchBinding:
        """Atomically claim the one-shot opaque handle for the bound task."""

        return self.__registry.consume(self)

    def retire(self) -> None:
        """Destroy local authority without asserting Worker success."""

        self.__registry.retire(self)

    def _identity(
        self,
    ) -> tuple[
        AgenticSpecialistDispatchBindingRegistry,
        asyncio.Task[object],
        object,
        str,
        tuple[tuple[str, str], ...],
        object,
    ]:
        return (
            self.__registry,
            self.__task,
            self.__token,
            self.__binding_digest,
            self.__identities,
            self.__runtime_token,
        )


class AgenticSpecialistDispatchBindingRegistry(_UncopyableProcessAuthority):
    """Exact-store, exact-task one-shot registry for C3C dispatch bindings."""

    __slots__ = (
        "__available",
        "__binding",
        "__consumed",
        "__database",
        "__lock",
        "__owner_tasks",
        "__registration",
        "__seen_identities",
        "__store",
        "__store_id",
        "__tombstones",
        "__weakref__",
    )
    __available: dict[str, _BindingRegistryEntry]
    __binding: AgenticCoordinationBinding
    __consumed: dict[str, _BindingRegistryEntry]
    __database: _LinuxPinnedCoordinationDatabase
    __lock: RLockType
    __owner_tasks: set[asyncio.Task[object]]
    __registration: object | None
    __seen_identities: set[tuple[str, str]]
    __store: AgenticCoordinationStore
    __store_id: str
    __tombstones: dict[str, str]

    def __init_subclass__(cls) -> Never:
        raise TypeError("specialist dispatch binding registries cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("specialist dispatch binding registries are immutable")

    def __delattr__(self, _name: str) -> Never:
        raise AttributeError("specialist dispatch binding registries are immutable")

    def __init__(self, *, store: AgenticCoordinationStore) -> None:
        if type(store) is not AgenticCoordinationStore:
            raise TypeError("specialist dispatch registry requires its exact coordination Store")
        database = store._database
        if type(database) is not _LinuxPinnedCoordinationDatabase:
            raise AgenticSpecialistDispatchBindingError(
                "specialist dispatch registry Store identity changed"
            )
        try:
            with _STORE_BINDING_OPERATION(store, database):
                binding = _strict_coordination_binding(store)
                prefix = "_AgenticSpecialistDispatchBindingRegistry__"
                object.__setattr__(self, prefix + "store", store)
                object.__setattr__(self, prefix + "store_id", store.store_id)
                object.__setattr__(self, prefix + "binding", binding)
                object.__setattr__(self, prefix + "database", database)
                object.__setattr__(self, prefix + "lock", threading.RLock())
                object.__setattr__(self, prefix + "available", {})
                object.__setattr__(self, prefix + "consumed", {})
                object.__setattr__(self, prefix + "tombstones", {})
                object.__setattr__(self, prefix + "seen_identities", set())
                object.__setattr__(self, prefix + "owner_tasks", set())
                registration = _STORE_REGISTRY_REGISTER(store, self)
                object.__setattr__(self, prefix + "registration", registration)
        except AgenticSpecialistDispatchBindingError:
            raise
        except Exception as exc:
            raise AgenticSpecialistDispatchBindingError(
                "specialist dispatch registry Store authority is closed or foreign"
            ) from exc

    def bind(
        self,
        started: VerifiedPlannedSpecialistDispatchStarted,
    ) -> VerifiedAgenticSpecialistDispatchBinding:
        """Consume one C3B2 started handle and publish one task-local C3C handle."""

        task = _current_task()
        with self._runtime_operation() as (store, coordination):
            try:
                runtime = _STARTED_HANDLE_TRANSFER(store, started)
            except Exception as exc:
                raise AgenticSpecialistDispatchBindingError(
                    "specialist dispatch started authority is foreign or consumed"
                ) from exc
            binding = _build_dispatch_binding(
                store=store,
                coordination=coordination,
                started=started,
                preparation=runtime.preparation,
            )
            canonical = _strict_dispatch_binding(binding)
            identities = _binding_identities(canonical)
            token = object()
            handle = VerifiedAgenticSpecialistDispatchBinding(
                binding_id=canonical.binding_id,
                binding_digest=canonical.binding_digest,
                identities=identities,
                registry=self,
                runtime_token=runtime._binding_identity_token(),
                task=task,
                token=token,
            )
            entry = _BindingRegistryEntry(
                handle=handle,
                binding=canonical,
                owner_task=task,
                token=token,
                runtime=runtime,
                binding_id=canonical.binding_id,
                binding_digest=canonical.binding_digest,
                identities=identities,
            )
            register_owner_task = False
            with self.__lock:
                if (
                    canonical.binding_id in self.__available
                    or canonical.binding_id in self.__consumed
                    or canonical.binding_id in self.__tombstones
                    or any(identity in self.__seen_identities for identity in identities)
                ):
                    raise AgenticSpecialistDispatchBindingError(
                        "specialist dispatch identity is already bound or tombstoned"
                    )
                self.__available[canonical.binding_id] = entry
                self.__seen_identities.update(identities)
                if task not in self.__owner_tasks:
                    self.__owner_tasks.add(task)
                    register_owner_task = True
            if register_owner_task:
                task.add_done_callback(self._owner_task_done)
        return handle

    def describe(
        self,
        handle: VerifiedAgenticSpecialistDispatchBinding,
    ) -> AgenticSpecialistDispatchBinding:
        """Return detached audit bytes without advancing the one-shot state."""

        binding_id = _exact_handle_binding_id(handle)
        task = _current_task()
        with self._runtime_operation(), self.__lock:
            entry = self.__available.get(binding_id) or self.__consumed.get(binding_id)
            binding = self._require_handle_entry(
                handle,
                entry,
                binding_id=binding_id,
                task=task,
            )
            return _strict_dispatch_binding(binding)

    def consume(
        self,
        handle: VerifiedAgenticSpecialistDispatchBinding,
    ) -> VerifiedAgenticSpecialistDispatchBinding:
        """Advance one opaque handle without degrading it into audit bytes."""

        binding_id = _exact_handle_binding_id(handle)
        task = _current_task()
        with self._runtime_operation(), self.__lock:
            entry = self.__available.get(binding_id)
            self._require_handle_entry(
                handle,
                entry,
                binding_id=binding_id,
                task=task,
            )
            assert entry is not None
            try:
                with _STORE_RUNTIME_CLAIM(self.__store, entry.runtime):
                    del self.__available[binding_id]
                    self.__consumed[binding_id] = entry
            except Exception as exc:
                if self.__available.get(binding_id) is entry:
                    del self.__available[binding_id]
                elif self.__consumed.get(binding_id) is entry:
                    del self.__consumed[binding_id]
                self.__tombstones[binding_id] = entry.binding_digest
                self._drop_owner_task_callback_if_unused(task)
                raise AgenticSpecialistDispatchBindingError(
                    "specialist dispatch runtime authority changed before claim"
                ) from exc
            return handle

    def retire(self, handle: VerifiedAgenticSpecialistDispatchBinding) -> None:
        """Destroy local authority without claiming Worker or execution success."""

        binding_id = _exact_handle_binding_id(handle)
        task = _current_task()
        with self._runtime_operation(), self.__lock:
            entry = self.__consumed.get(binding_id)
            binding = self._require_handle_entry(
                handle,
                entry,
                binding_id=binding_id,
                task=task,
            )
            del self.__consumed[binding_id]
            self.__tombstones[binding_id] = binding.binding_digest
            self._drop_owner_task_callback_if_unused(task)

    def state(self, binding_id: str) -> AgenticSpecialistDispatchBindingState:
        """Read the local lifecycle without returning any authority object.

        A terminal tombstone remains observable after Store shutdown because it
        contains no runtime capsule or bearer authority.
        """

        if type(binding_id) is not str:
            raise TypeError("specialist dispatch Binding ID must be a string")
        with self.__lock:
            if binding_id in self.__tombstones:
                return AgenticSpecialistDispatchBindingState.RETIRED
        try:
            with self._runtime_operation(), self.__lock:
                if binding_id in self.__available:
                    return AgenticSpecialistDispatchBindingState.AVAILABLE
                if binding_id in self.__consumed:
                    return AgenticSpecialistDispatchBindingState.CONSUMED
                if binding_id in self.__tombstones:
                    return AgenticSpecialistDispatchBindingState.RETIRED
            raise AgenticSpecialistDispatchBindingError("specialist dispatch binding is unknown")
        except AgenticSpecialistDispatchBindingError:
            with self.__lock:
                if binding_id in self.__tombstones:
                    return AgenticSpecialistDispatchBindingState.RETIRED
            raise

    @contextmanager
    def _runtime_operation(
        self,
    ) -> Iterator[tuple[AgenticCoordinationStore, AgenticCoordinationBinding]]:
        store = self.__store
        if (
            type(self) is not AgenticSpecialistDispatchBindingRegistry
            or type(store) is not AgenticCoordinationStore
            or store._database is not self.__database
            or AgenticCoordinationStore._specialist_dispatch_binding_operation
            is not _STORE_BINDING_OPERATION
            or AgenticCoordinationStore._claim_transferred_specialist_dispatch_runtime
            is not _STORE_RUNTIME_CLAIM
            or AgenticCoordinationStore._register_specialist_dispatch_binding_registry
            is not _STORE_REGISTRY_REGISTER
        ):
            raise AgenticSpecialistDispatchBindingError(
                "specialist dispatch registry Store identity changed"
            )
        try:
            with _STORE_BINDING_OPERATION(store, self.__database):
                runtime_store, binding = self._exact_runtime()
                yield runtime_store, binding
                if self._exact_runtime() != (runtime_store, binding):
                    raise AgenticSpecialistDispatchBindingError(
                        "specialist dispatch registry deployment binding changed"
                    )
        except AgenticSpecialistDispatchBindingError:
            raise
        except Exception as exc:
            raise AgenticSpecialistDispatchBindingError(
                "specialist dispatch registry Store authority is closed or foreign"
            ) from exc

    def _exact_runtime(self) -> tuple[AgenticCoordinationStore, AgenticCoordinationBinding]:
        store = self.__store
        database = store._database
        if (
            type(self) is not AgenticSpecialistDispatchBindingRegistry
            or type(store) is not AgenticCoordinationStore
            or store.store_id != self.__store_id
            or database is not self.__database
            or AgenticCoordinationStore._transfer_planned_specialist_dispatch_started
            is not _STARTED_HANDLE_TRANSFER
            or AgenticCoordinationStore._specialist_dispatch_binding_operation
            is not _STORE_BINDING_OPERATION
            or AgenticCoordinationStore._claim_transferred_specialist_dispatch_runtime
            is not _STORE_RUNTIME_CLAIM
            or AgenticCoordinationStore._register_specialist_dispatch_binding_registry
            is not _STORE_REGISTRY_REGISTER
        ):
            raise AgenticSpecialistDispatchBindingError(
                "specialist dispatch registry Store identity changed"
            )
        try:
            self.__database.require_open()
        except Exception as exc:
            raise AgenticSpecialistDispatchBindingError(
                "specialist dispatch registry Store authority is closed or foreign"
            ) from exc
        binding = _strict_coordination_binding(store)
        if store._database is not database or binding != self.__binding:
            raise AgenticSpecialistDispatchBindingError(
                "specialist dispatch registry deployment binding changed"
            )
        return store, binding

    def _require_handle_entry(
        self,
        handle: VerifiedAgenticSpecialistDispatchBinding,
        entry: _BindingRegistryEntry | None,
        *,
        binding_id: str,
        task: asyncio.Task[object],
    ) -> AgenticSpecialistDispatchBinding:
        if (
            type(handle) is not VerifiedAgenticSpecialistDispatchBinding
            or type(entry) is not _BindingRegistryEntry
        ):
            raise AgenticSpecialistDispatchBindingError(
                "specialist dispatch handle is absent, foreign, or consumed"
            )
        assert entry is not None
        registry, owner_task, token, binding_digest, identities, runtime_token = handle._identity()
        binding = _strict_dispatch_binding(entry.binding)
        if (
            registry is not self
            or entry.handle is not handle
            or owner_task is not task
            or entry.owner_task is not task
            or token is not entry.token
            or binding_id != handle.binding_id
            or binding_id != entry.binding_id
            or binding_id != binding.binding_id
            or binding_digest != entry.binding_digest
            or binding_digest != binding.binding_digest
            or identities != entry.identities
            or identities != _binding_identities(binding)
            or type(entry.runtime) is not _AgenticSpecialistDispatchRuntimeCapsule
            or runtime_token is not entry.runtime._binding_identity_token()
        ):
            raise AgenticSpecialistDispatchBindingError(
                "specialist dispatch handle is absent, foreign, or consumed"
            )
        return binding

    def _owner_task_done(self, task: asyncio.Task[object]) -> None:
        """Destroy any local capsule stranded when its owner Task terminates."""

        with self.__lock:
            for entries in (self.__available, self.__consumed):
                for binding_id, entry in tuple(entries.items()):
                    if type(entry) is not _BindingRegistryEntry:
                        del entries[binding_id]
                        continue
                    if entry.owner_task is task:
                        del entries[binding_id]
                        self.__tombstones[binding_id] = entry.binding_digest
            self.__owner_tasks.discard(task)

    def _abandon_from_store(
        self,
        store: AgenticCoordinationStore,
        registration: object,
    ) -> None:
        """Tombstone and zeroize every capsule when the exact Store closes."""

        if (
            type(self) is not AgenticSpecialistDispatchBindingRegistry
            or type(store) is not AgenticCoordinationStore
            or store is not self.__store
            or registration is not self.__registration
        ):
            raise AgenticSpecialistDispatchBindingError(
                "specialist dispatch registry Store abandon identity changed"
            )
        invalid_entry = False
        with self.__lock:
            for entries in (self.__available, self.__consumed):
                for binding_id, entry in tuple(entries.items()):
                    if type(entry) is not _BindingRegistryEntry:
                        invalid_entry = True
                        continue
                    self.__tombstones[binding_id] = entry.binding_digest
                entries.clear()
            owner_tasks = tuple(self.__owner_tasks)
            self.__owner_tasks.clear()
            object.__setattr__(
                self,
                "_AgenticSpecialistDispatchBindingRegistry__registration",
                None,
            )
        for owner_task in owner_tasks:
            with suppress(RuntimeError):
                owner_task.get_loop().call_soon_threadsafe(
                    owner_task.remove_done_callback,
                    self._owner_task_done,
                )
        if invalid_entry:
            raise AgenticSpecialistDispatchBindingError(
                "specialist dispatch registry entry identity changed during Store abandon"
            )

    def _drop_owner_task_callback_if_unused(
        self,
        task: asyncio.Task[object],
    ) -> None:
        if any(
            type(entry) is _BindingRegistryEntry and entry.owner_task is task
            for entries in (self.__available, self.__consumed)
            for entry in entries.values()
        ):
            return
        task.remove_done_callback(self._owner_task_done)
        self.__owner_tasks.discard(task)


_REGISTRY_STORE_ABANDON_IMPLEMENTATION = (
    AgenticSpecialistDispatchBindingRegistry._abandon_from_store
)


def _exact_handle_binding_id(
    handle: VerifiedAgenticSpecialistDispatchBinding,
) -> str:
    if type(handle) is not VerifiedAgenticSpecialistDispatchBinding:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch handle is absent, foreign, or consumed"
        )
    return handle.binding_id


def _current_task() -> asyncio.Task[object]:
    task = asyncio.current_task()
    if task is None:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch binding requires an active asyncio Task"
        )
    return cast(asyncio.Task[object], task)


def _strict_coordination_binding(
    store: AgenticCoordinationStore,
) -> AgenticCoordinationBinding:
    if type(store) is not AgenticCoordinationStore:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch coordination binding failed strict reload"
        )
    binding_value = store.binding
    if type(binding_value) is not AgenticCoordinationBinding:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch coordination binding failed strict reload"
        )
    try:
        binding = AgenticCoordinationBinding.model_validate(
            binding_value.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValueError, WebSpecialistExecutorError) as exc:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch coordination binding failed strict reload"
        ) from exc
    if store.binding is not binding_value or binding != binding_value:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch coordination binding differs after strict reload"
        )
    return binding


def _strict_dispatch_binding(
    binding: AgenticSpecialistDispatchBinding,
) -> AgenticSpecialistDispatchBinding:
    if type(binding) is not AgenticSpecialistDispatchBinding:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch binding failed strict reload"
        )
    try:
        canonical = AgenticSpecialistDispatchBinding.model_validate(
            binding.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch binding failed strict reload"
        ) from exc
    if type(binding) is not AgenticSpecialistDispatchBinding or canonical != binding:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch binding differs after strict reload"
        )
    return canonical


def _strict_preparation(
    preparation: AgenticSpecialistPreparation,
) -> AgenticSpecialistPreparation:
    if type(preparation) is not AgenticSpecialistPreparation:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch preparation failed strict reload"
        )
    try:
        canonical = AgenticSpecialistPreparation.model_validate(
            preparation.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch preparation failed strict reload"
        ) from exc
    if type(preparation) is not AgenticSpecialistPreparation or canonical != preparation:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch preparation differs after strict reload"
        )
    return canonical


def _strict_started(
    started: VerifiedPlannedSpecialistDispatchStarted,
) -> tuple[AgenticSpecialistDispatchPlanEntry, AgenticSpecialistExecutionEntry]:
    if type(started) is not VerifiedPlannedSpecialistDispatchStarted:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch binding requires its exact C3B2 started handle"
        )
    plan_value = started.plan
    execution_value = started.execution
    permit = started.permit
    approval_receipt = started.approval_receipt
    grant_receipt = started.grant_consumption_receipt
    if (
        type(plan_value) is not AgenticSpecialistDispatchPlanEntry
        or type(execution_value) is not AgenticSpecialistExecutionEntry
        or type(permit) is not ActionPermit
        or type(approval_receipt) is not ActionApprovalConsumptionReceipt
        or type(grant_receipt) is not AgenticSpecialistCapabilityGrantConsumptionReceipt
    ):
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch started state failed strict reload"
        )
    try:
        plan = AgenticSpecialistDispatchPlanEntry.model_validate(
            plan_value.model_dump(mode="json", by_alias=True)
        )
        execution = AgenticSpecialistExecutionEntry.model_validate(
            execution_value.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch started state failed strict reload"
        ) from exc
    if (
        plan != plan_value
        or execution != execution_value
        or plan.state is not AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        or execution.state is not AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        or plan.action_permit != permit
        or plan.approval_consumption_receipt != approval_receipt
        or plan.grant_consumption_receipt != grant_receipt
    ):
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch started state is not one exact C3B2 fence"
        )
    return plan, execution


def _resolve_profile_and_executor(
    preparation: AgenticSpecialistPreparation,
) -> SpecialistExecutorDescriptor:
    try:
        profiles = production_web_specialist_execution_profile_catalog()
        profile = profiles.resolve(preparation.profile)
        executors = production_web_specialist_executor_catalog()
        descriptor = executors.resolve(profile)
    except (AttributeError, TypeError, ValueError) as exc:
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch profile or executor is not current"
        ) from exc
    if (
        profiles.registry_digest != preparation.profile_registry_digest
        or descriptor.catalog_digest != preparation.executor_catalog_digest
        or descriptor.profile_registry_digest != preparation.profile_registry_digest
        or descriptor.profile_ref != preparation.profile
        or descriptor.executor_id != preparation.executor_id
        or descriptor.executor_version != preparation.executor_version
        or descriptor.executor_digest != preparation.executor_digest
        or descriptor.diagnostic_steps != preparation.diagnostic_steps
        or descriptor.promotable_steps != preparation.promotable_steps
    ):
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch profile or executor binding drifted"
        )
    return descriptor


def _build_dispatch_binding(
    *,
    store: AgenticCoordinationStore,
    coordination: AgenticCoordinationBinding,
    started: VerifiedPlannedSpecialistDispatchStarted,
    preparation: AgenticSpecialistPreparation,
) -> AgenticSpecialistDispatchBinding:
    plan, execution = _strict_started(started)
    prepared = _strict_preparation(preparation)
    descriptor = _resolve_profile_and_executor(prepared)
    action = plan.prepared_action
    capability = action.capability
    request = action.request
    permit = started.permit
    approval_receipt = started.approval_receipt
    grant_receipt = started.grant_consumption_receipt

    if (
        plan.store_id != store.store_id
        or execution.store_id != store.store_id
        or prepared.store_id != store.store_id
        or plan.coordination_binding_digest != coordination.binding_digest
        or execution.coordination_binding_digest != coordination.binding_digest
        or prepared.coordination_binding_id != coordination.binding_id
        or prepared.coordination_binding_digest != coordination.binding_digest
        or plan.control_plane_run_id != coordination.control_plane_run_id
        or prepared.control_plane_run_id != coordination.control_plane_run_id
        or prepared.deployment_digest != coordination.deployment_digest
        or plan.campaign_id != coordination.campaign_id
        or prepared.campaign_id != coordination.campaign_id
        or plan.campaign_manifest_digest != coordination.campaign_manifest_digest
        or prepared.campaign_manifest_digest != coordination.campaign_manifest_digest
    ):
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch Store or deployment identity differs"
        )
    if (
        plan.reservation_id != execution.reservation_id
        or plan.reservation_digest != execution.reservation_digest
        or plan.command_id != execution.command_id
        or plan.command_digest != execution.command_digest
        or plan.target_agent_id != execution.target_agent_id
        or plan.task_id != execution.task_id
        or plan.specialization is not execution.specialization
        or plan.preparation_id != prepared.preparation_id
        or plan.preparation_digest != prepared.preparation_digest
        or prepared.reservation_id != execution.reservation_id
        or prepared.reservation_digest != execution.reservation_digest
        or prepared.reservation_state_digest != plan.reservation_state_digest
        or prepared.command_id != execution.command_id
        or prepared.command_digest != execution.command_digest
        or prepared.target_agent_id != execution.target_agent_id
        or prepared.task_id != execution.task_id
        or prepared.specialization is not execution.specialization
    ):
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch plan, reservation, command, preparation, or task differs"
        )
    if (
        plan.profile_id != prepared.profile.profile_id
        or plan.profile_version != prepared.profile.profile_version
        or plan.profile_digest != prepared.profile.profile_digest
        or plan.executor_id != descriptor.executor_id
        or plan.executor_digest != descriptor.executor_digest
        or plan.target_id != prepared.target_id
        or plan.target_endpoint != prepared.target_endpoint
        or plan.target_digest != prepared.target_digest
        or plan.activation_set_digest != action.activation_set_digest
        or plan.release_id != action.release.release_id
        or plan.release_digest != action.release.release_digest
        or plan.capability_id != capability.capability_id
        or plan.capability_version != capability.capability_version
        or plan.capability_digest != capability.definition_digest
        or plan.tool_id != capability.tool_id
        or request.tool_id != capability.tool_id
        or plan.prepared_action_digest
        != discovery_digest(
            "pajin.agentic.prepared-specialist-action/v1",
            action.model_dump(mode="json", by_alias=True),
        )
    ):
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch profile, executor, Capability, Tool, or action differs"
        )
    if (
        plan.grant.grant_id != grant_receipt.capability_grant_id
        or plan.grant.grant_digest != grant_receipt.capability_grant_digest
        or plan.grant.subject != plan.target_agent_id
        or plan.grant.tools != (request.tool_id,)
        or plan.grant.targets != (prepared.target_endpoint,)
        or grant_receipt.plan_id != plan.plan_id
        or grant_receipt.plan_digest != plan.plan_digest
        or grant_receipt.store_id != store.store_id
        or grant_receipt.coordination_binding_digest != coordination.binding_digest
        or grant_receipt.reservation_id != execution.reservation_id
        or grant_receipt.reservation_digest != execution.reservation_digest
        or grant_receipt.command_id != execution.command_id
        or grant_receipt.command_digest != execution.command_digest
        or grant_receipt.action_permit_id != permit.permit_id
        or grant_receipt.action_permit_digest != permit.permit_digest
        or grant_receipt.approval_consumption_receipt_id != approval_receipt.receipt_id
        or grant_receipt.approval_consumption_receipt_digest != approval_receipt.receipt_digest
    ):
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch Grant or Grant-consumption receipt differs"
        )
    if (
        permit != plan.action_permit
        or approval_receipt != plan.approval_consumption_receipt
        or approval_receipt.action_permit != permit
        or approval_receipt.approval != plan.approval_envelope
        or permit.request_id != request.request_id
        or permit.request_digest != action.request_digest
        or permit.capability != capability
        or permit.target_digest != prepared.target_digest
    ):
        raise AgenticSpecialistDispatchBindingError(
            "specialist dispatch request, Permit, or approval receipt differs"
        )

    return AgenticSpecialistDispatchBinding(
        storeId=store.store_id,
        coordinationBindingId=coordination.binding_id,
        coordinationBindingDigest=coordination.binding_digest,
        controlPlaneRunId=coordination.control_plane_run_id,
        deploymentDigest=coordination.deployment_digest,
        campaignId=coordination.campaign_id,
        campaignManifestDigest=coordination.campaign_manifest_digest,
        planId=plan.plan_id,
        planDigest=plan.plan_digest,
        planStateDigest=plan.state_digest,
        reservationId=execution.reservation_id,
        reservationDigest=execution.reservation_digest,
        reservationStateDigest=execution.state_digest,
        reservationSourceStateDigest=plan.reservation_state_digest,
        commandId=execution.command_id,
        commandDigest=execution.command_digest,
        preparationId=prepared.preparation_id,
        preparationDigest=prepared.preparation_digest,
        preparedActionDigest=plan.prepared_action_digest,
        profileRegistryDigest=prepared.profile_registry_digest,
        profileId=prepared.profile.profile_id,
        profileVersion=prepared.profile.profile_version,
        profileDigest=prepared.profile.profile_digest,
        executorCatalogDigest=descriptor.catalog_digest,
        executorId=descriptor.executor_id,
        executorVersion=descriptor.executor_version,
        executorDigest=descriptor.executor_digest,
        activationSetDigest=action.activation_set_digest,
        releaseId=action.release.release_id,
        releaseDigest=action.release.release_digest,
        capabilityId=capability.capability_id,
        capabilityVersion=capability.capability_version,
        capabilityDefinitionDigest=capability.definition_digest,
        capabilityDigest=capability.capability_digest,
        toolId=capability.tool_id,
        toolVersion=capability.tool_version,
        toolDigest=capability.tool_digest,
        requestId=request.request_id,
        requestDigest=action.request_digest,
        capabilityGrantId=plan.grant.grant_id,
        capabilityGrantDigest=plan.grant.grant_digest,
        grantConsumptionReceiptId=grant_receipt.receipt_id,
        grantConsumptionReceiptDigest=grant_receipt.receipt_digest,
        actionPermitId=permit.permit_id,
        actionPermitDigest=permit.permit_digest,
        approvalId=plan.approval_envelope.approval_id,
        approvalDigest=plan.approval_envelope.approval_digest,
        approvalConsumptionReceiptId=approval_receipt.receipt_id,
        approvalConsumptionReceiptDigest=approval_receipt.receipt_digest,
        dispatchId=permit.dispatch_id,
        targetAgentId=execution.target_agent_id,
        taskId=execution.task_id,
        targetId=prepared.target_id,
        targetDigest=prepared.target_digest,
        specialization=execution.specialization,
    )


def _binding_identities(
    binding: AgenticSpecialistDispatchBinding,
) -> tuple[tuple[str, str], ...]:
    return (
        ("binding", binding.binding_id),
        ("plan", binding.plan_id),
        ("reservation", binding.reservation_id),
        ("command", binding.command_id),
        ("preparation", binding.preparation_id),
        ("request", binding.request_id),
        ("grant-receipt", binding.grant_consumption_receipt_id),
        ("permit", binding.action_permit_id),
        ("approval-receipt", binding.approval_consumption_receipt_id),
    )


__all__ = [
    "AGENTIC_SPECIALIST_DISPATCH_BINDING_API_VERSION",
    "AgenticSpecialistDispatchBinding",
    "AgenticSpecialistDispatchBindingError",
    "AgenticSpecialistDispatchBindingRegistry",
    "AgenticSpecialistDispatchBindingState",
    "VerifiedAgenticSpecialistDispatchBinding",
]
