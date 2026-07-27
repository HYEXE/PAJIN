"""Verified CAP-005 signed-release and benchmark-mapping rollout."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.existing import (
    ExistingModeCapabilityBundle,
)
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleError,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
)
from pajin.capabilities.metrics import (
    CapabilityDeliveryEvidence,
    CapabilityOracleObservation,
    CapabilityRegistryMetricsReport,
    CapabilityReplayObservation,
    build_capability_registry_metrics,
    existing_mode_capability_metric_scope,
    existing_mode_capability_replay_support,
)
from pajin.capabilities.models import (
    CapabilityDefinitionRef,
    CapabilityMaturity,
    capability_definition_digest,
)
from pajin.capabilities.scaffold import CapabilityBenchmarkMapping
from pajin.domain.models import StrictModel

EXISTING_MODE_CAPABILITY_RELEASE_SET_API_VERSION: Literal[
    "pajin.dev/existing-mode-capability-release-set/v1alpha1"
] = "pajin.dev/existing-mode-capability-release-set/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_EXPECTED_CAPABILITY_COUNT = 7

_BENCHMARK_CONTRACTS: dict[str, tuple[str, str]] = {
    "pajin.ai.kisa.indirect-tool-hijacking": (
        "pajin.benchmark.kisa.agent.indirect-tool-hijacking",
        "The host validates the authorized mock simulation and expected catalog observation.",
    ),
    "pajin.ai.kisa.jailbreak-policy-bypass": (
        "pajin.benchmark.kisa.model.jailbreak-policy-bypass",
        "The host recomputes every KISA catalog check from the normalized transcript.",
    ),
    "pajin.ai.kisa.memory-poisoning-persistence": (
        "pajin.benchmark.kisa.agent.memory-poisoning-persistence",
        "The host recomputes every KISA catalog check from the normalized transcript.",
    ),
    "pajin.ai.kisa.system-prompt-disclosure": (
        "pajin.benchmark.kisa.model.system-prompt-disclosure",
        "The host recomputes every KISA catalog check from the normalized transcript.",
    ),
    "pajin.bug-bounty.boolean-sqli-lab": (
        "pajin.benchmark.bug-bounty.boolean-sqli-lab",
        "The host recomputes baseline, negative-control, and boolean-probe predicates.",
    ),
    "pajin.ctf.crypto-single-byte-xor": (
        "pajin.benchmark.ctf.crypto-single-byte-xor",
        "The host recomputes all 256 XOR keys from the content-addressed artifact.",
    ),
    "pajin.ctf.web-exposed-backup-config": (
        "pajin.benchmark.ctf.web-exposed-backup-config",
        "Typed request and result identities yield an exposed backup configuration candidate.",
    ),
}


class ExistingModeCapabilityRolloutError(ValueError):
    """Raised when a CAP-005 release set is incomplete or identity-drifted."""


class ExistingModeCapabilityReleaseBinding(StrictModel):
    """One exact CAP-005 authority, signed bundle, and benchmark mapping."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    capability: CodeBackedCapabilityRef
    release: CapabilityReleaseRef
    release_bundle_digest: _Sha256 = Field(alias="releaseBundleDigest")
    benchmark_mapping_digest: _Sha256 = Field(alias="benchmarkMappingDigest")
    maturity: CapabilityMaturity

    @model_validator(mode="after")
    def require_experimental_release(self) -> Self:
        if self.maturity is not CapabilityMaturity.EXPERIMENTAL:
            raise ValueError("existing Mode first rollout must remain experimental")
        return self


class ExistingModeCapabilityReleaseSet(StrictModel):
    """Content-addressed inventory of seven externally reviewed signed releases."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/existing-mode-capability-release-set/v1alpha1"] = Field(
        default=EXISTING_MODE_CAPABILITY_RELEASE_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ExistingModeCapabilityReleaseSet"] = "ExistingModeCapabilityReleaseSet"
    release_set_id: str = Field(default="", alias="releaseSetId", max_length=90)
    release_set_digest: str = Field(
        default="",
        alias="releaseSetDigest",
        max_length=64,
    )
    adapter_version: Literal["pajin.existing-mode-capability-adapter/v1"] = Field(
        default="pajin.existing-mode-capability-adapter/v1",
        alias="adapterVersion",
    )
    policy_digest: _Sha256 = Field(alias="policyDigest")
    bindings: tuple[ExistingModeCapabilityReleaseBinding, ...] = Field(
        min_length=_EXPECTED_CAPABILITY_COUNT,
        max_length=_EXPECTED_CAPABILITY_COUNT,
    )

    @model_validator(mode="after")
    def bind_release_set_identity(self) -> Self:
        keys = [_binding_key(item) for item in self.bindings]
        if keys != sorted(set(keys)):
            raise ValueError("existing Mode release bindings must be unique and canonically sorted")
        capability_ids = [
            _binding_capability(item).capability.capability_id for item in self.bindings
        ]
        if len(capability_ids) != len(set(capability_ids)):
            raise ValueError(
                "existing Mode release set cannot contain multiple versions of a Capability"
            )
        release_keys = [
            (item.release.release_id, item.release.release_digest) for item in self.bindings
        ]
        if len(release_keys) != len(set(release_keys)):
            raise ValueError("existing Mode signed release is duplicated")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"release_set_id", "release_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.existing-mode-release-set/v1",
            material,
        )
        release_set_id = f"existing-mode-release-set_{digest}"
        if self.release_set_digest and self.release_set_digest != digest:
            raise ValueError("existing Mode release-set digest differs from canonical identity")
        if self.release_set_id and self.release_set_id != release_set_id:
            raise ValueError("existing Mode release-set ID differs from canonical identity")
        object.__setattr__(self, "release_set_digest", digest)
        object.__setattr__(self, "release_set_id", release_set_id)
        return self


@dataclass(frozen=True, slots=True)
class ExistingModeCapabilityRollout:
    """Verified runtime objects and their immutable release-set audit record."""

    bundle: ExistingModeCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    release_set: ExistingModeCapabilityReleaseSet
    benchmark_mappings: tuple[CapabilityBenchmarkMapping, ...]

    def __post_init__(self) -> None:
        _verify_rollout(self)


def existing_mode_capability_benchmark_mappings(
    bundle: ExistingModeCapabilityBundle,
) -> tuple[CapabilityBenchmarkMapping, ...]:
    """Return the closed CAP-003 mappings for all seven CAP-005 adapters."""

    if not isinstance(bundle, ExistingModeCapabilityBundle):
        raise TypeError("existing Mode benchmark mappings require their exact bundle")
    mappings: list[CapabilityBenchmarkMapping] = []
    for capability in bundle.capabilities():
        capability_id = capability.capability.capability_id
        try:
            benchmark_id, observable = _BENCHMARK_CONTRACTS[capability_id]
        except KeyError as exc:
            raise ExistingModeCapabilityRolloutError(
                "existing Mode Capability lacks an explicit benchmark contract"
            ) from exc
        mappings.append(
            CapabilityBenchmarkMapping(
                capability=capability.capability,
                benchmarkIds=(benchmark_id,),
                expectedObservables=(observable,),
            )
        )
    if len(mappings) != _EXPECTED_CAPABILITY_COUNT:
        raise ExistingModeCapabilityRolloutError(
            "existing Mode benchmark inventory must contain exactly seven Capabilities"
        )
    return tuple(sorted(mappings, key=lambda item: _definition_key(item.capability)))


def admit_existing_mode_capability_releases(
    *,
    bundle: ExistingModeCapabilityBundle,
    policy: CapabilityLifecyclePolicy,
    trust_keys: Iterable[CapabilityLifecycleTrustKey],
    releases: Iterable[CapabilityReleaseBundle],
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ExistingModeCapabilityRollout:
    """Verify seven externally signed first releases without generating signing authority."""

    if not isinstance(bundle, ExistingModeCapabilityBundle):
        raise TypeError("existing Mode rollout requires its exact Capability bundle")
    canonical_policy = _canonical_model(
        policy,
        CapabilityLifecyclePolicy,
        label="lifecycle policy",
    )
    canonical_keys = tuple(
        _canonical_model(
            item,
            CapabilityLifecycleTrustKey,
            label="lifecycle trust key",
        )
        for item in trust_keys
    )
    canonical_releases = tuple(
        _canonical_model(
            item,
            CapabilityReleaseBundle,
            label="signed release bundle",
        )
        for item in releases
    )
    if len(canonical_releases) != _EXPECTED_CAPABILITY_COUNT:
        raise ExistingModeCapabilityRolloutError(
            "existing Mode rollout requires exactly seven signed first releases"
        )
    try:
        lifecycle = CapabilityLifecycleRegistry(
            definitions=bundle.definitions,
            authorities=bundle.authorities,
            policy=canonical_policy,
            trust_keys=canonical_keys,
            releases=canonical_releases,
            clock=clock,
        )
    except CapabilityLifecycleError as exc:
        raise ExistingModeCapabilityRolloutError(
            "existing Mode signed release set failed lifecycle verification"
        ) from exc

    mappings = existing_mode_capability_benchmark_mappings(bundle)
    release_bundles = {
        _capability_key(item.release.statement.capability): item for item in canonical_releases
    }
    if len(release_bundles) != _EXPECTED_CAPABILITY_COUNT:
        raise ExistingModeCapabilityRolloutError(
            "existing Mode rollout contains duplicate Capability releases"
        )
    mapping_by_definition = {_definition_key(item.capability): item for item in mappings}
    bindings: list[ExistingModeCapabilityReleaseBinding] = []
    for capability in bundle.capabilities():
        reference = capability.reference()
        key = _capability_key(reference)
        try:
            signed_bundle = release_bundles[key]
            mapping = mapping_by_definition[_definition_key(reference.capability)]
            head = lifecycle.head(reference.capability.capability_id)
        except (KeyError, CapabilityLifecycleError) as exc:
            raise ExistingModeCapabilityRolloutError(
                "existing Mode rollout does not cover the exact seven-Capability inventory"
            ) from exc
        statement = signed_bundle.release.statement
        if head != statement.reference():
            raise ExistingModeCapabilityRolloutError(
                "existing Mode release is not the verified lifecycle head"
            )
        bindings.append(
            ExistingModeCapabilityReleaseBinding(
                capability=reference,
                release=statement.reference(),
                releaseBundleDigest=_release_bundle_digest(signed_bundle),
                benchmarkMappingDigest=mapping.mapping_digest,
                maturity=statement.maturity,
            )
        )
    release_set = ExistingModeCapabilityReleaseSet(
        policyDigest=canonical_policy.digest,
        bindings=tuple(sorted(bindings, key=_binding_key)),
    )
    return ExistingModeCapabilityRollout(
        bundle=bundle,
        lifecycle=lifecycle,
        release_set=release_set,
        benchmark_mappings=mappings,
    )


def existing_mode_capability_rollout_metrics(
    rollout: ExistingModeCapabilityRollout,
    *,
    measured_at: datetime,
    delivery_evidence: Iterable[CapabilityDeliveryEvidence] = (),
    oracle_observations: Iterable[CapabilityOracleObservation] = (),
    replay_observations: Iterable[CapabilityReplayObservation] = (),
) -> CapabilityRegistryMetricsReport:
    """Measure a verified rollout while leaving absent operational evidence explicit."""

    if not isinstance(rollout, ExistingModeCapabilityRollout):
        raise TypeError("existing Mode rollout metrics require a verified rollout")
    _verify_rollout(rollout)
    return build_capability_registry_metrics(
        scope=existing_mode_capability_metric_scope(rollout.bundle),
        definitions=rollout.bundle.definitions,
        authorities=rollout.bundle.authorities,
        measured_at=measured_at,
        benchmark_mappings=rollout.benchmark_mappings,
        delivery_evidence=delivery_evidence,
        oracle_observations=oracle_observations,
        replay_support=existing_mode_capability_replay_support(rollout.bundle),
        replay_observations=replay_observations,
        lifecycle=rollout.lifecycle,
    )


def _verify_rollout(rollout: ExistingModeCapabilityRollout) -> None:
    if not isinstance(rollout.bundle, ExistingModeCapabilityBundle):
        raise TypeError("existing Mode rollout bundle is invalid")
    if not isinstance(rollout.lifecycle, CapabilityLifecycleRegistry):
        raise TypeError("existing Mode rollout lifecycle is invalid")
    try:
        release_set = ExistingModeCapabilityReleaseSet.model_validate(
            rollout.release_set.model_dump(mode="json", by_alias=True)
        )
        mappings = tuple(
            CapabilityBenchmarkMapping.model_validate(item.model_dump(mode="json", by_alias=True))
            for item in rollout.benchmark_mappings
        )
    except (AttributeError, ValidationError) as exc:
        raise ExistingModeCapabilityRolloutError(
            "existing Mode rollout artifacts are not canonical"
        ) from exc
    expected_mappings = existing_mode_capability_benchmark_mappings(rollout.bundle)
    if mappings != expected_mappings:
        raise ExistingModeCapabilityRolloutError(
            "existing Mode rollout benchmark mappings differ from code authority"
        )
    binding_by_capability = {
        _capability_key(_binding_capability(item)): item for item in release_set.bindings
    }
    if len(binding_by_capability) != _EXPECTED_CAPABILITY_COUNT:
        raise ExistingModeCapabilityRolloutError(
            "existing Mode release-set inventory is incomplete"
        )
    mappings_by_definition = {_definition_key(item.capability): item for item in mappings}
    for capability in rollout.bundle.capabilities():
        reference = capability.reference()
        try:
            binding = binding_by_capability[_capability_key(reference)]
            mapping = mappings_by_definition[_definition_key(reference.capability)]
            head = rollout.lifecycle.head(reference.capability.capability_id)
            signed_bundle = rollout.lifecycle.resolve_release(head)
        except (KeyError, CapabilityLifecycleError) as exc:
            raise ExistingModeCapabilityRolloutError(
                "existing Mode rollout cannot resolve an exact release binding"
            ) from exc
        statement = signed_bundle.release.statement
        if (
            binding.release != head
            or statement.capability != reference
            or statement.policy_digest != release_set.policy_digest
            or binding.release_bundle_digest != _release_bundle_digest(signed_bundle)
            or binding.benchmark_mapping_digest != mapping.mapping_digest
            or binding.maturity is not statement.maturity
        ):
            raise ExistingModeCapabilityRolloutError(
                "existing Mode rollout release binding drifted"
            )


def _canonical_model[ModelT: StrictModel](
    value: ModelT,
    model_type: type[ModelT],
    *,
    label: str,
) -> ModelT:
    try:
        return model_type.model_validate(value.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise ExistingModeCapabilityRolloutError(f"existing Mode {label} is not canonical") from exc


def _release_bundle_digest(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.capability.existing-mode-release-bundle/v1",
        bundle.model_dump(mode="json", by_alias=True),
    )


def _binding_capability(
    binding: ExistingModeCapabilityReleaseBinding,
) -> CodeBackedCapabilityRef:
    return binding.capability


def _binding_key(
    binding: ExistingModeCapabilityReleaseBinding,
) -> tuple[str, str, str, str]:
    return _capability_key(_binding_capability(binding))


def _definition_key(reference: CapabilityDefinitionRef) -> tuple[str, str, str]:
    return (
        reference.capability_id,
        reference.capability_version,
        reference.capability_digest,
    )


def _capability_key(reference: CodeBackedCapabilityRef) -> tuple[str, str, str, str]:
    return (
        reference.capability.capability_id,
        reference.capability.capability_version,
        reference.capability.capability_digest,
        reference.authority_set_digest,
    )
