"""Exact code-backed authority interfaces for versioned Capabilities."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal, Protocol, Self, cast, runtime_checkable

from pydantic import ConfigDict, Field, JsonValue, ValidationError, model_validator

from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityDefinitionError,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    canonical_capability_json,
    capability_definition_digest,
)
from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.runtime.stable_context import stable_execution_context
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult

CODE_BACKED_CAPABILITY_API_VERSION: Literal[
    "pajin.dev/code-backed-capability/v1alpha1"
] = "pajin.dev/code-backed-capability/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_AUTHORITY_SET_ID_PATTERN = r"^capability-authority-set_[a-f0-9]{64}$"
_SENSITIVE_CONTEXT_KEY_PARTS = frozenset(
    {
        "api-key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "passwd",
        "password",
        "secret",
        "token",
    }
)


class CapabilityAuthorityError(ValueError):
    """Raised when a code-backed Capability authority is unavailable or drifts."""


class CapabilityAuthorityRole(StrEnum):
    """Required code-owned roles behind one executable Capability."""

    ACTION_COMPILER = "action-compiler"
    CLEANUP_HANDLER = "cleanup-handler"
    EXECUTOR_ADAPTER = "executor-adapter"
    MATERIALIZER = "materializer"
    REPLAY_STRATEGY = "replay-strategy"
    RESULT_NORMALIZER = "result-normalizer"
    SUCCESS_ORACLE = "success-oracle"


class CapabilityOracleDecision(StrEnum):
    """Bounded semantic outcome returned by a Capability success Oracle."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class CapabilityAuthorityAdapter(Protocol):
    """Common immutable identity required from every code-backed adapter."""

    @property
    def authority_role(self) -> CapabilityAuthorityRole: ...

    @property
    def authority_id(self) -> str: ...

    @property
    def authority_version(self) -> str: ...

    @property
    def capability_reference(self) -> CapabilityDefinitionRef: ...

    def stable_execution_context(self) -> Mapping[str, object]:
        """Return explicit, non-secret configuration without mutating authority state."""


@runtime_checkable
class CapabilityMaterializer(CapabilityAuthorityAdapter, Protocol):
    """Normalize bounded proposal parameters without creating execution authority."""

    def materialize(
        self,
        parameters: Mapping[str, JsonValue],
    ) -> Mapping[str, JsonValue]: ...


@runtime_checkable
class CapabilityActionCompiler(CapabilityAuthorityAdapter, Protocol):
    """Compile normalized parameters into one exact existing Tool request."""

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest: ...


@runtime_checkable
class CapabilityExecutorAdapter(CapabilityAuthorityAdapter, Protocol):
    """Prepare an isolated Worker job for one already-authorized Tool request."""

    def prepare(self, request: ToolRequest) -> WorkerJob: ...


@runtime_checkable
class CapabilityResultNormalizer(CapabilityAuthorityAdapter, Protocol):
    """Normalize bounded Worker output into the existing Tool result contract."""

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult: ...


@runtime_checkable
class CapabilitySuccessOracle(CapabilityAuthorityAdapter, Protocol):
    """Classify normalized Tool output without creating Finding authority."""

    def evaluate(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> CapabilityOracleDecision: ...


@runtime_checkable
class CapabilityReplayStrategy(CapabilityAuthorityAdapter, Protocol):
    """Produce a non-executable replay plan that must be separately authorized."""

    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None: ...


@runtime_checkable
class CapabilityCleanupHandler(CapabilityAuthorityAdapter, Protocol):
    """Produce a non-executable cleanup plan that must receive a new Permit."""

    def plan_cleanup(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None: ...


class CapabilityAuthorityBinding(StrictModel):
    """Exact code identity for one role in a code-backed Capability."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    role: CapabilityAuthorityRole
    authority_id: _Identifier = Field(alias="authorityId")
    authority_version: _Identifier = Field(alias="authorityVersion")
    implementation_type: str = Field(
        alias="implementationType",
        min_length=1,
        max_length=500,
    )
    context_digest: _Sha256 = Field(alias="contextDigest")
    authority_digest: _Sha256 = Field(alias="authorityDigest")


class CodeBackedCapabilityRef(StrictModel):
    """Exact definition and authority-set identity required for resolution."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    capability: CapabilityDefinitionRef
    authority_set_id: str = Field(
        alias="authoritySetId",
        pattern=_AUTHORITY_SET_ID_PATTERN,
    )
    authority_set_digest: _Sha256 = Field(alias="authoritySetDigest")


class CodeBackedCapability(StrictModel):
    """Immutable binding from CAP-001 metadata to all required code authorities."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/code-backed-capability/v1alpha1"] = Field(
        default=CODE_BACKED_CAPABILITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CodeBackedCapability"] = "CodeBackedCapability"
    authority_set_id: str = Field(default="", alias="authoritySetId", max_length=89)
    authority_set_digest: str = Field(default="", alias="authoritySetDigest", max_length=64)
    capability: CapabilityDefinitionRef
    authorities: tuple[CapabilityAuthorityBinding, ...] = Field(
        min_length=len(CapabilityAuthorityRole),
        max_length=len(CapabilityAuthorityRole),
    )

    @model_validator(mode="after")
    def bind_authority_set_identity(self) -> Self:
        roles = [item.role.value for item in self.authorities]
        expected = sorted(role.value for role in CapabilityAuthorityRole)
        if roles != expected:
            raise ValueError(
                "code-backed Capability authorities must contain every role once in sorted order"
            )
        authority_identities = [
            (item.authority_id, item.authority_version) for item in self.authorities
        ]
        if len(authority_identities) != len(set(authority_identities)):
            raise ValueError("code-backed Capability authority identities must be unique")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_set_id", "authority_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.authority-set/v1",
            material,
        )
        authority_set_id = f"capability-authority-set_{digest}"
        if self.authority_set_digest and self.authority_set_digest != digest:
            raise ValueError("Capability authority-set digest differs from canonical identity")
        if self.authority_set_id and self.authority_set_id != authority_set_id:
            raise ValueError("Capability authority-set ID differs from canonical identity")
        object.__setattr__(self, "authority_set_digest", digest)
        object.__setattr__(self, "authority_set_id", authority_set_id)
        canonical_capability_json(
            self.model_dump(mode="json", by_alias=True),
            label="CodeBackedCapability",
        )
        return self

    def reference(self) -> CodeBackedCapabilityRef:
        """Return a detached exact reference to this code-backed authority set."""

        return CodeBackedCapabilityRef(
            capability=self.capability,
            authoritySetId=self.authority_set_id,
            authoritySetDigest=self.authority_set_digest,
        )


@dataclass(frozen=True, slots=True)
class RegisteredCapabilityAuthority:
    """Identity-checking wrapper around one mutable code adapter."""

    _adapter: CapabilityAuthorityAdapter
    _definition: CapabilityDefinition
    _binding: CapabilityAuthorityBinding

    @property
    def role(self) -> CapabilityAuthorityRole:
        return self._binding.role

    @property
    def binding(self) -> CapabilityAuthorityBinding:
        return self._binding.model_copy(deep=True)

    @property
    def capability(self) -> CapabilityDefinitionRef:
        return self._definition.reference()

    def validate_adapter_identity(self) -> None:
        """Fail if identity, type, stable context, or interface changed after registration."""

        try:
            capability, binding = _authority_identity(self._adapter)
        except (AttributeError, CapabilityAuthorityError, TypeError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "registered Capability authority identity changed"
            ) from exc
        if capability != self._definition.reference() or binding != self._binding:
            raise CapabilityAuthorityError("registered Capability authority identity changed")

    def validate_declared_identity(self) -> None:
        """Recheck declared identity without executing adapter stable-context code."""

        try:
            role, authority_id, authority_version, capability = _declared_authority_identity(
                self._adapter
            )
        except (AttributeError, CapabilityAuthorityError, TypeError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "registered Capability authority identity changed"
            ) from exc
        if (
            role != self._binding.role
            or authority_id != self._binding.authority_id
            or authority_version != self._binding.authority_version
            or capability != self._definition.reference()
        ):
            raise CapabilityAuthorityError("registered Capability authority identity changed")

    def materialize(
        self,
        parameters: Mapping[str, JsonValue],
    ) -> dict[str, JsonValue]:
        self._require_role(CapabilityAuthorityRole.MATERIALIZER)
        canonical = _canonical_json_mapping(parameters, label="Capability parameters")
        self.validate_adapter_identity()
        try:
            result = cast(CapabilityMaterializer, self._adapter).materialize(canonical)
        finally:
            self.validate_adapter_identity()
        return _canonical_json_mapping(result, label="Capability materialization")

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        self._require_role(CapabilityAuthorityRole.ACTION_COMPILER)
        trusted_request = self._bound_request(
            request,
            label="Capability compiler request",
        )
        trusted_arguments = _canonical_json_mapping(
            materialized_arguments,
            label="Capability materialized arguments",
        )
        self.validate_adapter_identity()
        try:
            result = cast(CapabilityActionCompiler, self._adapter).compile(
                trusted_request,
                trusted_arguments,
            )
        finally:
            self.validate_adapter_identity()
        compiled = _canonical_model(
            ToolRequest,
            result,
            label="Capability compiled request",
        )
        if (
            compiled.request_id != trusted_request.request_id
            or compiled.agent_id != trusted_request.agent_id
            or compiled.target != trusted_request.target
            or compiled.method != trusted_request.method
            or compiled.tool_id != self._definition.tool.tool_id
            or canonical_capability_json(
                compiled.arguments,
                label="Capability compiled arguments",
            )
            != canonical_capability_json(
                trusted_arguments,
                label="Capability trusted materialized arguments",
            )
        ):
            raise CapabilityAuthorityError(
                "Capability compiler expanded or changed exact request authority"
            )
        return compiled

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self._require_role(CapabilityAuthorityRole.EXECUTOR_ADAPTER)
        trusted_request = self._bound_request(request, label="Capability executor request")
        self.validate_adapter_identity()
        try:
            result = cast(CapabilityExecutorAdapter, self._adapter).prepare(trusted_request)
        finally:
            self.validate_adapter_identity()
        job = _canonical_model(WorkerJob, result, label="Capability Worker job")
        if not self._definition.network_access and job.network is not NetworkMode.NONE:
            raise CapabilityAuthorityError(
                "network-disabled Capability prepared a network-enabled Worker job"
            )
        return job

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        self._require_role(CapabilityAuthorityRole.RESULT_NORMALIZER)
        trusted_request = self._bound_request(request, label="Capability normalizer request")
        trusted_result = _canonical_model(
            WorkerResult,
            result,
            label="Capability Worker result",
        )
        self.validate_adapter_identity()
        try:
            normalized = cast(CapabilityResultNormalizer, self._adapter).normalize(
                trusted_request,
                trusted_result,
            )
        finally:
            self.validate_adapter_identity()
        normalized = _canonical_model(
            ToolResult,
            normalized,
            label="Capability normalized result",
        )
        if (
            normalized.request_id != trusted_request.request_id
            or normalized.tool_id != self._definition.tool.tool_id
        ):
            raise CapabilityAuthorityError(
                "Capability normalizer changed request or Tool identity"
            )
        return normalized

    def evaluate(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> CapabilityOracleDecision:
        self._require_role(CapabilityAuthorityRole.SUCCESS_ORACLE)
        trusted_request = self._bound_request(request, label="Capability Oracle request")
        trusted_result = self._bound_result(result, request=trusted_request)
        self.validate_adapter_identity()
        try:
            decision = cast(CapabilitySuccessOracle, self._adapter).evaluate(
                trusted_request,
                trusted_result,
            )
        finally:
            self.validate_adapter_identity()
        try:
            return CapabilityOracleDecision(decision)
        except ValueError as exc:
            raise CapabilityAuthorityError(
                "Capability Oracle returned an unsupported decision"
            ) from exc

    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> dict[str, JsonValue] | None:
        self._require_role(CapabilityAuthorityRole.REPLAY_STRATEGY)
        trusted_request = self._bound_request(request, label="Capability replay request")
        trusted_result = self._bound_result(result, request=trusted_request)
        self.validate_adapter_identity()
        try:
            plan = cast(CapabilityReplayStrategy, self._adapter).plan_replay(
                trusted_request,
                trusted_result,
            )
        finally:
            self.validate_adapter_identity()
        return (
            None
            if plan is None
            else _canonical_json_mapping(plan, label="Capability replay plan")
        )

    def plan_cleanup(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> dict[str, JsonValue] | None:
        self._require_role(CapabilityAuthorityRole.CLEANUP_HANDLER)
        trusted_request = self._bound_request(request, label="Capability cleanup request")
        trusted_result = self._bound_result(result, request=trusted_request)
        self.validate_adapter_identity()
        try:
            plan = cast(CapabilityCleanupHandler, self._adapter).plan_cleanup(
                trusted_request,
                trusted_result,
            )
        finally:
            self.validate_adapter_identity()
        return (
            None
            if plan is None
            else _canonical_json_mapping(plan, label="Capability cleanup plan")
        )

    def _bound_request(self, request: ToolRequest, *, label: str) -> ToolRequest:
        trusted = _canonical_model(ToolRequest, request, label=label)
        if trusted.tool_id != self._definition.tool.tool_id:
            raise CapabilityAuthorityError(
                "Capability authority request uses another registered Tool"
            )
        return trusted

    def _bound_result(self, result: ToolResult, *, request: ToolRequest) -> ToolResult:
        trusted = _canonical_model(
            ToolResult,
            result,
            label="Capability Tool result",
        )
        if (
            trusted.request_id != request.request_id
            or trusted.tool_id != self._definition.tool.tool_id
        ):
            raise CapabilityAuthorityError(
                "Capability Tool result differs from exact request identity"
            )
        return trusted

    def _require_role(self, expected: CapabilityAuthorityRole) -> None:
        if self.role is not expected:
            raise CapabilityAuthorityError(
                f"Capability authority role {self.role.value} cannot perform {expected.value}"
            )


class CapabilityAuthorityRegistry:
    """Frozen exact registry for complete code-backed Capability authority sets."""

    def __init__(
        self,
        definitions: CapabilityDefinitionRegistry,
        authorities: Iterable[CapabilityAuthorityAdapter],
    ) -> None:
        if not isinstance(definitions, CapabilityDefinitionRegistry):
            raise TypeError("Capability authorities require a CapabilityDefinitionRegistry")
        handles: dict[
            tuple[str, str, str, CapabilityAuthorityRole],
            RegisteredCapabilityAuthority,
        ] = {}
        identities: set[tuple[str, str]] = set()
        grouped: dict[
            tuple[str, str, str],
            list[RegisteredCapabilityAuthority],
        ] = {}
        for adapter in authorities:
            capability, binding = _authority_identity(adapter)
            try:
                definition = definitions.resolve(capability)
            except CapabilityDefinitionError as exc:
                raise CapabilityAuthorityError(
                    "Capability authority references an unregistered definition"
                ) from exc
            identity = (binding.authority_id, binding.authority_version)
            if identity in identities:
                raise CapabilityAuthorityError(
                    "Capability authority ID and version are registered more than once"
                )
            identities.add(identity)
            key = _capability_key(capability)
            handle_key = (*key, binding.role)
            if handle_key in handles:
                raise CapabilityAuthorityError(
                    "Capability authority role is registered more than once"
                )
            handle = RegisteredCapabilityAuthority(adapter, definition, binding)
            handle.validate_adapter_identity()
            handles[handle_key] = handle
            grouped.setdefault(key, []).append(handle)

        if not grouped:
            raise CapabilityAuthorityError(
                "Capability authority registry requires at least one complete set"
            )

        manifests: dict[tuple[str, str, str], CodeBackedCapability] = {}
        for key, capability_handles in grouped.items():
            observed = {item.role for item in capability_handles}
            missing = set(CapabilityAuthorityRole) - observed
            if missing:
                names = ", ".join(sorted(item.value for item in missing))
                raise CapabilityAuthorityError(
                    f"code-backed Capability is missing required authorities: {names}"
                )
            manifest = CodeBackedCapability(
                capability=capability_handles[0].capability,
                authorities=tuple(
                    sorted(
                        (item.binding for item in capability_handles),
                        key=lambda item: item.role.value,
                    )
                ),
            )
            manifests[key] = manifest

        self._handles = handles
        self._manifests = manifests
        for manifest in self._manifests.values():
            self._validate_manifest_handles(manifest)

    def resolve(self, reference: CodeBackedCapabilityRef) -> CodeBackedCapability:
        """Resolve only an exact definition and authority-set identity."""

        try:
            manifest = self._manifests[_capability_key(reference.capability)]
        except KeyError as exc:
            raise CapabilityAuthorityError(
                "code-backed Capability is not registered"
            ) from exc
        if manifest.reference() != reference:
            raise CapabilityAuthorityError(
                "Capability authority-set ID or digest differs from the registry"
            )
        self._validate_manifest_handles(manifest)
        return manifest.model_copy(deep=True)

    def authority(
        self,
        reference: CodeBackedCapabilityRef,
        role: CapabilityAuthorityRole,
    ) -> RegisteredCapabilityAuthority:
        """Return one identity-checking role wrapper from an exact authority set."""

        manifest = self.resolve(reference)
        key = (*_capability_key(manifest.capability), CapabilityAuthorityRole(role))
        try:
            handle = self._handles[key]
        except KeyError as exc:
            raise CapabilityAuthorityError(
                "Capability authority role is not registered"
            ) from exc
        handle.validate_adapter_identity()
        return handle

    def capabilities(self) -> tuple[CodeBackedCapability, ...]:
        """Return detached manifests in canonical Capability order."""

        manifests = []
        for key in sorted(self._manifests):
            manifest = self._manifests[key]
            self._validate_manifest_handles(manifest)
            manifests.append(manifest.model_copy(deep=True))
        return tuple(manifests)

    def _validate_manifest_handles(self, manifest: CodeBackedCapability) -> None:
        # Consecutive observations catch drift that persists across context reads.
        # A final context-free sweep catches scalar drift introduced by the last read.
        for _ in range(2):
            for binding in manifest.authorities:
                key = (*_capability_key(manifest.capability), binding.role)
                handle = self._handles.get(key)
                if handle is None or handle.binding != binding:
                    raise CapabilityAuthorityError(
                        "Capability authority set differs from registered code"
                    )
                handle.validate_adapter_identity()
        for binding in manifest.authorities:
            key = (*_capability_key(manifest.capability), binding.role)
            handle = self._handles.get(key)
            if handle is None:
                raise CapabilityAuthorityError(
                    "Capability authority set differs from registered code"
                )
            handle.validate_declared_identity()


def capability_authority_binding(
    authority: CapabilityAuthorityAdapter,
) -> CapabilityAuthorityBinding:
    """Return the canonical public binding for one code-backed adapter."""

    return _authority_identity(authority)[1]


def _authority_identity(
    adapter: CapabilityAuthorityAdapter,
) -> tuple[CapabilityDefinitionRef, CapabilityAuthorityBinding]:
    role, authority_id, authority_version, capability = _declared_authority_identity(adapter)
    _require_role_interface(adapter, role)
    try:
        stable = stable_execution_context(
            adapter,
            component=f"Capability authority {authority_id}@{authority_version}",
        )
        current_role, current_authority_id, current_authority_version, current_capability = (
            _declared_authority_identity(adapter)
        )
        if (
            current_role != role
            or current_authority_id != authority_id
            or current_authority_version != authority_version
            or current_capability != capability
        ):
            raise CapabilityAuthorityError(
                "Capability authority identity changed while capturing stable context"
            )
        implementation_type = cast(str, stable["type"])
        context = stable["context"]
        _reject_sensitive_context(context, path="context")
        context_digest = capability_definition_digest(
            "pajin.capability.authority-context/v1",
            {
                "implementationType": implementation_type,
                "context": context,
            },
        )
        authority_digest = capability_definition_digest(
            "pajin.capability.authority/v1",
            {
                "role": role.value,
                "authorityId": authority_id,
                "authorityVersion": authority_version,
                "capability": capability.model_dump(mode="json", by_alias=True),
                "implementationType": implementation_type,
                "contextDigest": context_digest,
            },
        )
        binding = CapabilityAuthorityBinding(
            role=role,
            authorityId=authority_id,
            authorityVersion=authority_version,
            implementationType=implementation_type,
            contextDigest=context_digest,
            authorityDigest=authority_digest,
        )
    except (
        CapabilityDefinitionError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise CapabilityAuthorityError(
            "Capability authority stable context is invalid"
        ) from exc
    return capability, binding


def _declared_authority_identity(
    adapter: CapabilityAuthorityAdapter,
) -> tuple[CapabilityAuthorityRole, str, str, CapabilityDefinitionRef]:
    try:
        return (
            CapabilityAuthorityRole(adapter.authority_role),
            adapter.authority_id,
            adapter.authority_version,
            CapabilityDefinitionRef.model_validate(
                adapter.capability_reference.model_dump(mode="json", by_alias=True)
            ),
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise CapabilityAuthorityError(
            "Capability authority does not expose a canonical identity"
        ) from exc


def _require_role_interface(
    adapter: CapabilityAuthorityAdapter,
    role: CapabilityAuthorityRole,
) -> None:
    matches = {
        CapabilityAuthorityRole.MATERIALIZER: isinstance(adapter, CapabilityMaterializer),
        CapabilityAuthorityRole.ACTION_COMPILER: isinstance(
            adapter,
            CapabilityActionCompiler,
        ),
        CapabilityAuthorityRole.EXECUTOR_ADAPTER: isinstance(
            adapter,
            CapabilityExecutorAdapter,
        ),
        CapabilityAuthorityRole.RESULT_NORMALIZER: isinstance(
            adapter,
            CapabilityResultNormalizer,
        ),
        CapabilityAuthorityRole.SUCCESS_ORACLE: isinstance(
            adapter,
            CapabilitySuccessOracle,
        ),
        CapabilityAuthorityRole.REPLAY_STRATEGY: isinstance(
            adapter,
            CapabilityReplayStrategy,
        ),
        CapabilityAuthorityRole.CLEANUP_HANDLER: isinstance(
            adapter,
            CapabilityCleanupHandler,
        ),
    }
    if not matches[role]:
        raise CapabilityAuthorityError(
            f"Capability authority does not implement its {role.value} interface"
        )


def _canonical_json_mapping(
    value: Mapping[str, JsonValue],
    *,
    label: str,
) -> dict[str, JsonValue]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise CapabilityAuthorityError(f"{label} must be a string-keyed JSON object")
    try:
        encoded = canonical_capability_json(dict(value), label=label)
        decoded = json.loads(encoded)
    except (CapabilityDefinitionError, TypeError, UnicodeError, ValueError) as exc:
        raise CapabilityAuthorityError(f"{label} is not bounded canonical JSON") from exc
    if not isinstance(decoded, dict):
        raise CapabilityAuthorityError(f"{label} must be a JSON object")
    return cast(dict[str, JsonValue], decoded)


def _canonical_model[ModelT](
    model_type: type[ModelT],
    value: object,
    *,
    label: str,
) -> ModelT:
    try:
        dump = value.model_dump(mode="json")  # type: ignore[attr-defined]
        encoded = canonical_capability_json(dump, label=label)
        return model_type.model_validate_json(encoded)  # type: ignore[attr-defined,no-any-return]
    except (
        AttributeError,
        CapabilityDefinitionError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise CapabilityAuthorityError(f"{label} is not canonical") from exc


def _reject_sensitive_context(value: object, *, path: str) -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                raise CapabilityAuthorityError(
                    "Capability authority context keys must be strings"
                )
            key_parts = _context_key_parts(raw_key)
            if (
                key_parts & _SENSITIVE_CONTEXT_KEY_PARTS
                and child is not None
                and not isinstance(child, bool)
            ):
                raise CapabilityAuthorityError(
                    f"Capability authority stable context contains secret-like field: {path}"
                )
            _reject_sensitive_context(child, path=f"{path}.{raw_key}")
        return
    if isinstance(value, list | tuple):
        for index, child in enumerate(value):
            _reject_sensitive_context(child, path=f"{path}[{index}]")


def _context_key_parts(value: str) -> set[str]:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", value)
    lowered = separated.lower()
    parts = {part for part in re.split(r"[^a-z0-9]+", lowered) if part}
    collapsed = "".join(parts)
    if collapsed:
        parts.add(collapsed)
    return parts


def _capability_key(reference: CapabilityDefinitionRef) -> tuple[str, str, str]:
    return (
        reference.capability_id,
        reference.capability_version,
        reference.capability_digest,
    )
