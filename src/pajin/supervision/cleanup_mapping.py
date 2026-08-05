"""Code-owned source-to-cleanup Capability mapping authority."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from pydantic import ValidationError

from pajin.capabilities.activation import (
    ExistingModeCapabilityActivation,
    ExistingModeCapabilityActivationBinding,
    ExistingModeCapabilityActivationError,
    ExistingModeCapabilityActivationSet,
)
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.models import (
    CapabilityDefinitionError,
    canonical_capability_json,
    capability_definition_digest,
)
from pajin.runtime.stable_context import stable_execution_context

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_METHOD_PATTERN = re.compile(r"^[A-Z0-9!#$%&'*+.^_`|~-]{1,20}$")
_MAX_IMPLEMENTATION_TYPE_LENGTH = 500


class CleanupCapabilityMappingError(ValueError):
    """Raised when a source-to-cleanup code authority is absent or drifts."""


@runtime_checkable
class CleanupCapabilityMappingAdapter(Protocol):
    """Declare one exact source-to-cleanup mapping owned by code."""

    @property
    def authority_id(self) -> str: ...

    @property
    def authority_version(self) -> str: ...

    @property
    def source_capability(self) -> CodeBackedCapabilityRef: ...

    @property
    def cleanup_binding(self) -> ExistingModeCapabilityActivationBinding: ...

    @property
    def cleanup_method(self) -> str: ...

    def stable_execution_context(self) -> Mapping[str, object]:
        """Return bounded non-secret configuration that affects the mapping."""


@dataclass(frozen=True, slots=True)
class CleanupCapabilityMappingAuthorityBinding:
    """In-process identity of one code-owned mapping adapter."""

    authority_id: str
    authority_version: str
    implementation_type: str
    context_digest: str


@dataclass(frozen=True, slots=True)
class ResolvedCleanupCapabilityMapping:
    """Frozen current mapping result; this is not a persisted authority wire."""

    activation_set_digest: str
    source_capability: CodeBackedCapabilityRef
    cleanup_binding: ExistingModeCapabilityActivationBinding
    cleanup_method: str
    authority: CleanupCapabilityMappingAuthorityBinding
    mapping_digest: str


@dataclass(frozen=True, slots=True)
class RegisteredCleanupCapabilityMapping:
    """Identity-checking wrapper around one mutable mapping adapter."""

    _adapter: CleanupCapabilityMappingAdapter
    _expected: ResolvedCleanupCapabilityMapping

    @property
    def source_capability(self) -> CodeBackedCapabilityRef:
        return _canonical_reference(self._expected.source_capability)

    def resolve(
        self,
        activation: ExistingModeCapabilityActivation,
    ) -> ResolvedCleanupCapabilityMapping:
        """Revalidate code and current signed activation before returning a mapping."""

        observed = _mapping_identity(self._adapter, activation)
        if observed != self._expected:
            raise CleanupCapabilityMappingError(
                "registered cleanup Capability mapping identity changed"
            )
        return _detached_mapping(observed)


class CleanupCapabilityMappingRegistry:
    """Immutable exact registry keyed by one source code-backed Capability."""

    __slots__ = ("_activation", "_activation_set_digest", "_mappings")

    def __init__(
        self,
        *,
        activation: ExistingModeCapabilityActivation,
        adapters: Iterable[CleanupCapabilityMappingAdapter],
    ) -> None:
        if not isinstance(activation, ExistingModeCapabilityActivation):
            raise TypeError("cleanup Capability mappings require a verified activation")
        activation_set = _canonical_activation_set(activation)
        mappings: dict[tuple[str, str, str, str, str], RegisteredCleanupCapabilityMapping] = {}
        authority_identities: set[tuple[str, str]] = set()
        for adapter in adapters:
            expected = _mapping_identity(adapter, activation)
            key = _reference_key(expected.source_capability)
            if key in mappings:
                raise CleanupCapabilityMappingError(
                    "cleanup Capability mapping source is registered more than once"
                )
            authority_identity = (
                expected.authority.authority_id,
                expected.authority.authority_version,
            )
            if authority_identity in authority_identities:
                raise CleanupCapabilityMappingError(
                    "cleanup Capability mapping authority identity is registered more than once"
                )
            authority_identities.add(authority_identity)
            mappings[key] = RegisteredCleanupCapabilityMapping(adapter, expected)
        if not mappings:
            raise CleanupCapabilityMappingError(
                "cleanup Capability mapping registry requires at least one mapping"
            )
        self._activation = activation
        self._activation_set_digest = activation_set.activation_set_digest
        self._mappings = MappingProxyType(mappings)

    def resolve(
        self,
        source: CodeBackedCapabilityRef,
    ) -> ResolvedCleanupCapabilityMapping:
        """Resolve one exact source mapping with no latest or name fallback."""

        canonical_source = _canonical_reference(source)
        current_set = _canonical_activation_set(self._activation)
        if current_set.activation_set_digest != self._activation_set_digest:
            raise CleanupCapabilityMappingError("cleanup Capability mapping activation changed")
        try:
            registered = self._mappings[_reference_key(canonical_source)]
        except KeyError as exc:
            raise CleanupCapabilityMappingError(
                "cleanup Capability mapping is not registered for the exact source"
            ) from exc
        if registered.source_capability != canonical_source:
            raise CleanupCapabilityMappingError(
                "cleanup Capability mapping source authority differs"
            )
        return registered.resolve(self._activation)

    def mappings(self) -> tuple[ResolvedCleanupCapabilityMapping, ...]:
        """Return detached mappings in canonical source order after revalidation."""

        return tuple(
            self._mappings[key].resolve(self._activation) for key in sorted(self._mappings)
        )


def _mapping_identity(
    adapter: CleanupCapabilityMappingAdapter,
    activation: ExistingModeCapabilityActivation,
) -> ResolvedCleanupCapabilityMapping:
    if not isinstance(adapter, CleanupCapabilityMappingAdapter):
        raise CleanupCapabilityMappingError(
            "cleanup Capability mapping adapter does not implement its Protocol"
        )
    first = _declared_mapping(adapter)
    first_current = _resolve_current_mapping(activation, first[2], first[3])
    try:
        stable = stable_execution_context(
            adapter,
            component=f"Cleanup Capability mapping {first[0]}@{first[1]}",
        )
        canonical_capability_json(
            stable,
            label="Cleanup Capability mapping stable context",
        )
        second = _declared_mapping(adapter)
        second_current = _resolve_current_mapping(activation, second[2], second[3])
    except (
        AttributeError,
        CapabilityDefinitionError,
        ExistingModeCapabilityActivationError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise CleanupCapabilityMappingError(
            "cleanup Capability mapping adapter identity is invalid"
        ) from exc
    if first != second or first_current != second_current:
        raise CleanupCapabilityMappingError(
            "cleanup Capability mapping identity changed while capturing stable context"
        )
    authority_id, authority_version, source, _cleanup, method = second
    source_binding, cleanup_binding, activation_set = second_current
    implementation_type = stable["type"]
    if (
        not isinstance(implementation_type, str)
        or len(implementation_type) > _MAX_IMPLEMENTATION_TYPE_LENGTH
    ):
        raise CleanupCapabilityMappingError(
            "cleanup Capability mapping implementation type is invalid"
        )
    context_digest = capability_definition_digest(
        "pajin.capability.cleanup-mapping-context/v1",
        {"implementationType": implementation_type, "context": stable["context"]},
    )
    authority = CleanupCapabilityMappingAuthorityBinding(
        authority_id=authority_id,
        authority_version=authority_version,
        implementation_type=implementation_type,
        context_digest=context_digest,
    )
    material = {
        "activationSetDigest": activation_set.activation_set_digest,
        "sourceCapability": source.model_dump(mode="json", by_alias=True),
        "sourceActivationBinding": source_binding.model_dump(mode="json", by_alias=True),
        "cleanupBinding": cleanup_binding.model_dump(mode="json", by_alias=True),
        "cleanupMethod": method,
        "authority": {
            "authorityId": authority.authority_id,
            "authorityVersion": authority.authority_version,
            "implementationType": authority.implementation_type,
            "contextDigest": authority.context_digest,
        },
    }
    mapping_digest = capability_definition_digest(
        "pajin.capability.source-cleanup-mapping/v1",
        material,
    )
    return ResolvedCleanupCapabilityMapping(
        activation_set_digest=activation_set.activation_set_digest,
        source_capability=source,
        cleanup_binding=cleanup_binding,
        cleanup_method=method,
        authority=authority,
        mapping_digest=mapping_digest,
    )


def _declared_mapping(
    adapter: CleanupCapabilityMappingAdapter,
) -> tuple[
    str,
    str,
    CodeBackedCapabilityRef,
    ExistingModeCapabilityActivationBinding,
    str,
]:
    try:
        authority_id = adapter.authority_id
        authority_version = adapter.authority_version
        if (
            not isinstance(authority_id, str)
            or _IDENTIFIER_PATTERN.fullmatch(authority_id) is None
            or not isinstance(authority_version, str)
            or _IDENTIFIER_PATTERN.fullmatch(authority_version) is None
        ):
            raise ValueError("mapping authority identifier is not canonical")
        source = _canonical_reference(adapter.source_capability)
        cleanup = ExistingModeCapabilityActivationBinding.model_validate(
            adapter.cleanup_binding.model_dump(mode="json", by_alias=True)
        )
        method = adapter.cleanup_method
        if not isinstance(method, str) or _METHOD_PATTERN.fullmatch(method) is None:
            raise ValueError("cleanup method is not canonical or bounded")
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise CleanupCapabilityMappingError(
            "cleanup Capability mapping adapter does not expose a canonical declaration"
        ) from exc
    if source == cleanup.capability:
        raise CleanupCapabilityMappingError(
            "cleanup Capability mapping requires a distinct Capability"
        )
    return authority_id, authority_version, source, cleanup, method


def _resolve_current_mapping(
    activation: ExistingModeCapabilityActivation,
    source: CodeBackedCapabilityRef,
    declared_cleanup: ExistingModeCapabilityActivationBinding,
) -> tuple[
    ExistingModeCapabilityActivationBinding,
    ExistingModeCapabilityActivationBinding,
    ExistingModeCapabilityActivationSet,
]:
    activation_set = _canonical_activation_set(activation)
    source_matches = tuple(
        item for item in activation_set.bindings if item.capability == source
    )
    cleanup_matches = tuple(
        item
        for item in activation_set.bindings
        if item.capability == declared_cleanup.capability
    )
    if len(source_matches) != 1:
        raise CleanupCapabilityMappingError(
            "cleanup Capability mapping source activation is absent or ambiguous"
        )
    if len(cleanup_matches) != 1 or cleanup_matches[0] != declared_cleanup:
        raise CleanupCapabilityMappingError(
            "cleanup Capability mapping target is inactive, historical, or ambiguous"
        )
    source_binding = source_matches[0]
    cleanup_binding = cleanup_matches[0]
    try:
        source_resolved = activation.resolve_for_dispatch(
            source_binding.action_capability.reference()
        )
        cleanup_resolved = activation.resolve_for_dispatch(
            cleanup_binding.action_capability.reference()
        )
        if (
            source_resolved.release != source_binding.release
            or source_resolved.capability.reference() != source_binding.capability
            or cleanup_resolved.release != cleanup_binding.release
            or cleanup_resolved.capability.reference() != cleanup_binding.capability
        ):
            raise CleanupCapabilityMappingError(
                "cleanup Capability mapping activation resolution drifted"
            )
    except ExistingModeCapabilityActivationError as exc:
        raise CleanupCapabilityMappingError(
            "cleanup Capability mapping activation is not currently dispatchable"
        ) from exc
    return source_binding, cleanup_binding, activation_set


def _canonical_activation_set(
    activation: ExistingModeCapabilityActivation,
) -> ExistingModeCapabilityActivationSet:
    try:
        return ExistingModeCapabilityActivationSet.model_validate(
            activation.activation_set.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise CleanupCapabilityMappingError(
            "cleanup Capability mapping activation set is not canonical"
        ) from exc


def _canonical_reference(reference: CodeBackedCapabilityRef) -> CodeBackedCapabilityRef:
    try:
        return CodeBackedCapabilityRef.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise CleanupCapabilityMappingError(
            "cleanup Capability mapping source reference is not canonical"
        ) from exc


def _reference_key(reference: CodeBackedCapabilityRef) -> tuple[str, str, str, str, str]:
    definition = reference.capability
    return (
        definition.capability_id,
        definition.capability_version,
        definition.capability_digest,
        reference.authority_set_id,
        reference.authority_set_digest,
    )


def _detached_mapping(
    mapping: ResolvedCleanupCapabilityMapping,
) -> ResolvedCleanupCapabilityMapping:
    return ResolvedCleanupCapabilityMapping(
        activation_set_digest=mapping.activation_set_digest,
        source_capability=_canonical_reference(mapping.source_capability),
        cleanup_binding=ExistingModeCapabilityActivationBinding.model_validate(
            mapping.cleanup_binding.model_dump(mode="json", by_alias=True)
        ),
        cleanup_method=mapping.cleanup_method,
        authority=mapping.authority,
        mapping_digest=mapping.mapping_digest,
    )
