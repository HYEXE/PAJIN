from __future__ import annotations

from collections.abc import Mapping
from dataclasses import FrozenInstanceError, dataclass
from hashlib import sha256
from typing import cast

import pytest
from pydantic import JsonValue

from pajin.capabilities.activation import (
    ExistingModeCapabilityActivation,
    ExistingModeCapabilityActivationBinding,
    ExistingModeCapabilityActivationError,
    ExistingModeCapabilityActivationSet,
)
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.lifecycle import (
    CapabilityReleaseRef,
    CapabilityUseProfile,
    ResolvedCapabilityRelease,
)
from pajin.capabilities.models import CapabilityDefinitionRef
from pajin.capabilities.rollout import ExistingModeCapabilityRollout
from pajin.graph.authority import ActionCapabilityRef, RegisteredActionCapability
from pajin.supervision.cleanup_mapping import (
    CleanupCapabilityMappingError,
    CleanupCapabilityMappingRegistry,
)


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def _binding(name: str) -> ExistingModeCapabilityActivationBinding:
    definition_digest = _digest(f"definition:{name}")
    authority_digest = _digest(f"authority:{name}")
    capability = CodeBackedCapabilityRef(
        capability=CapabilityDefinitionRef(
            capabilityId=f"test.{name}",
            capabilityVersion="1.0.0",
            capabilityDigest=definition_digest,
        ),
        authoritySetId=f"capability-authority-set_{authority_digest}",
        authoritySetDigest=authority_digest,
    )
    action = RegisteredActionCapability(
        capabilityId=f"test.{name}",
        capabilityVersion="1.0.0",
        definitionDigest=definition_digest,
        toolId=f"test.{name}-tool",
        toolVersion="1.0.0",
        toolDigest=_digest(f"tool:{name}"),
        riskTier="T1",
    )
    release_digest = _digest(f"release:{name}")
    return ExistingModeCapabilityActivationBinding(
        release=CapabilityReleaseRef(
            releaseId=f"capability-release_{release_digest}",
            releaseDigest=release_digest,
        ),
        capability=capability,
        actionCapability=action,
        domain="bug-bounty",
        supportedSurfaceTypes=("http-api",),
    )


@dataclass(frozen=True, slots=True)
class _ResolvedCapability:
    _reference: CodeBackedCapabilityRef

    def reference(self) -> CodeBackedCapabilityRef:
        return self._reference.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class _ResolvedRelease:
    release: CapabilityReleaseRef
    capability: _ResolvedCapability


class _Activation(ExistingModeCapabilityActivation):
    def __init__(self, bindings: tuple[ExistingModeCapabilityActivationBinding, ...]) -> None:
        activation_set = ExistingModeCapabilityActivationSet(
            releaseSetDigest=_digest("release-set"),
            profile=CapabilityUseProfile.RANGE,
            bindings=tuple(
                sorted(
                    bindings,
                    key=lambda item: (
                        item.action_capability.capability_id,
                        item.action_capability.capability_version,
                        item.release.release_id,
                        item.release.release_digest,
                    ),
                )
            ),
        )
        object.__setattr__(
            self,
            "rollout",
            cast(ExistingModeCapabilityRollout, object()),
        )
        object.__setattr__(self, "activation_set", activation_set)
        object.__setattr__(self, "reject_dispatch", False)

    def resolve_for_dispatch(
        self,
        reference: ActionCapabilityRef,
    ) -> ResolvedCapabilityRelease:
        if self.reject_dispatch:
            raise ExistingModeCapabilityActivationError("fixture activation drifted")
        matches = tuple(
            item
            for item in self.activation_set.bindings
            if item.action_capability.reference() == reference
        )
        if len(matches) != 1:
            raise ExistingModeCapabilityActivationError("fixture activation is absent")
        binding = matches[0]
        return cast(
            ResolvedCapabilityRelease,
            _ResolvedRelease(
                release=binding.release,
                capability=_ResolvedCapability(binding.capability),
            ),
        )


class _MappingAdapter:
    def __init__(
        self,
        source: CodeBackedCapabilityRef,
        cleanup: ExistingModeCapabilityActivationBinding,
        *,
        authority_id: str = "pajin.cleanup.mapping.test",
        method: str = "DELETE",
    ) -> None:
        self._authority_id = authority_id
        self._authority_version = "1.0.0"
        self._source = source
        self._cleanup = cleanup
        self._method = method
        self.context: dict[str, JsonValue] = {"policy": "exact-single-cleanup"}

    @property
    def authority_id(self) -> str:
        return self._authority_id

    @property
    def authority_version(self) -> str:
        return self._authority_version

    @property
    def source_capability(self) -> CodeBackedCapabilityRef:
        return self._source

    @property
    def cleanup_binding(self) -> ExistingModeCapabilityActivationBinding:
        return self._cleanup

    @property
    def cleanup_method(self) -> str:
        return self._method

    def stable_execution_context(self) -> Mapping[str, object]:
        return dict(self.context)


@pytest.fixture
def mapping_inputs() -> tuple[
    _Activation,
    ExistingModeCapabilityActivationBinding,
    ExistingModeCapabilityActivationBinding,
]:
    source = _binding("source-write")
    cleanup = _binding("cleanup-restore")
    return _Activation((source, cleanup)), source, cleanup


def test_registry_resolves_one_deterministic_frozen_current_mapping(
    mapping_inputs: tuple[
        _Activation,
        ExistingModeCapabilityActivationBinding,
        ExistingModeCapabilityActivationBinding,
    ],
) -> None:
    activation, source, cleanup = mapping_inputs
    first_registry = CleanupCapabilityMappingRegistry(
        activation=activation,
        adapters=(_MappingAdapter(source.capability, cleanup),),
    )
    second_registry = CleanupCapabilityMappingRegistry(
        activation=activation,
        adapters=(_MappingAdapter(source.capability, cleanup),),
    )

    first = first_registry.resolve(source.capability)
    second = second_registry.resolve(source.capability)

    assert first == second
    assert first_registry.mappings() == (first,)
    assert first.activation_set_digest == activation.activation_set.activation_set_digest
    assert first.source_capability == source.capability
    assert first.cleanup_binding == cleanup
    assert first.cleanup_method == "DELETE"
    assert first.authority.authority_id == "pajin.cleanup.mapping.test"
    assert first.authority.authority_version == "1.0.0"
    assert first.authority.implementation_type.endswith("._MappingAdapter")
    assert len(first.authority.context_digest) == 64
    assert len(first.mapping_digest) == 64
    with pytest.raises(FrozenInstanceError):
        first.cleanup_method = "POST"  # type: ignore[misc]


def test_registry_rejects_duplicate_source_and_source_as_cleanup(
    mapping_inputs: tuple[
        _Activation,
        ExistingModeCapabilityActivationBinding,
        ExistingModeCapabilityActivationBinding,
    ],
) -> None:
    activation, source, cleanup = mapping_inputs
    with pytest.raises(CleanupCapabilityMappingError, match="source is registered more than once"):
        CleanupCapabilityMappingRegistry(
            activation=activation,
            adapters=(
                _MappingAdapter(source.capability, cleanup),
                _MappingAdapter(
                    source.capability,
                    cleanup,
                    authority_id="pajin.cleanup.mapping.second",
                ),
            ),
        )

    with pytest.raises(CleanupCapabilityMappingError, match="requires a distinct Capability"):
        CleanupCapabilityMappingRegistry(
            activation=activation,
            adapters=(_MappingAdapter(cleanup.capability, cleanup),),
        )


@pytest.mark.parametrize("method", ("delete", "D" * 21, ""))
def test_registry_rejects_noncanonical_identity_and_bounded_method(
    mapping_inputs: tuple[
        _Activation,
        ExistingModeCapabilityActivationBinding,
        ExistingModeCapabilityActivationBinding,
    ],
    method: str,
) -> None:
    activation, source, cleanup = mapping_inputs
    with pytest.raises(CleanupCapabilityMappingError, match="canonical declaration"):
        CleanupCapabilityMappingRegistry(
            activation=activation,
            adapters=(_MappingAdapter(source.capability, cleanup, method=method),),
        )

    with pytest.raises(CleanupCapabilityMappingError, match="canonical declaration"):
        CleanupCapabilityMappingRegistry(
            activation=activation,
            adapters=(
                _MappingAdapter(
                    source.capability,
                    cleanup,
                    authority_id="invalid mapping id",
                ),
            ),
        )


def test_registry_rejects_absent_and_historical_cleanup_mapping(
    mapping_inputs: tuple[
        _Activation,
        ExistingModeCapabilityActivationBinding,
        ExistingModeCapabilityActivationBinding,
    ],
) -> None:
    activation, source, cleanup = mapping_inputs
    registry = CleanupCapabilityMappingRegistry(
        activation=activation,
        adapters=(_MappingAdapter(source.capability, cleanup),),
    )
    with pytest.raises(CleanupCapabilityMappingError, match="not registered"):
        registry.resolve(_binding("other-source").capability)

    historical_digest = _digest("historical-cleanup-release")
    historical = cleanup.model_copy(
        update={
            "release": CapabilityReleaseRef(
                releaseId=f"capability-release_{historical_digest}",
                releaseDigest=historical_digest,
            )
        },
        deep=True,
    )
    with pytest.raises(CleanupCapabilityMappingError, match="inactive, historical, or ambiguous"):
        CleanupCapabilityMappingRegistry(
            activation=activation,
            adapters=(_MappingAdapter(source.capability, historical),),
        )


def test_registry_rejects_adapter_and_activation_drift(
    mapping_inputs: tuple[
        _Activation,
        ExistingModeCapabilityActivationBinding,
        ExistingModeCapabilityActivationBinding,
    ],
) -> None:
    activation, source, cleanup = mapping_inputs
    adapter = _MappingAdapter(source.capability, cleanup)
    registry = CleanupCapabilityMappingRegistry(
        activation=activation,
        adapters=(adapter,),
    )

    adapter._method = "PATCH"
    with pytest.raises(CleanupCapabilityMappingError, match="identity changed"):
        registry.resolve(source.capability)

    context_adapter = _MappingAdapter(source.capability, cleanup)
    context_registry = CleanupCapabilityMappingRegistry(
        activation=activation,
        adapters=(context_adapter,),
    )
    context_adapter.context["policy"] = "drifted"
    with pytest.raises(CleanupCapabilityMappingError, match="identity changed"):
        context_registry.resolve(source.capability)

    stable_adapter = _MappingAdapter(source.capability, cleanup)
    stable_registry = CleanupCapabilityMappingRegistry(
        activation=activation,
        adapters=(stable_adapter,),
    )
    object.__setattr__(activation, "reject_dispatch", True)
    with pytest.raises(CleanupCapabilityMappingError, match="currently dispatchable"):
        stable_registry.resolve(source.capability)


def test_registry_rejects_activation_set_replacement(
    mapping_inputs: tuple[
        _Activation,
        ExistingModeCapabilityActivationBinding,
        ExistingModeCapabilityActivationBinding,
    ],
) -> None:
    activation, source, cleanup = mapping_inputs
    registry = CleanupCapabilityMappingRegistry(
        activation=activation,
        adapters=(_MappingAdapter(source.capability, cleanup),),
    )
    replacement = ExistingModeCapabilityActivationSet(
        releaseSetDigest=_digest("another-release-set"),
        profile=activation.activation_set.profile,
        bindings=activation.activation_set.bindings,
    )
    object.__setattr__(activation, "activation_set", replacement)

    with pytest.raises(CleanupCapabilityMappingError, match="activation changed"):
        registry.resolve(source.capability)
