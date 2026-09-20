"""Inert, code-owned specialist execution-route profiles.

Profiles in this module describe a bounded diagnostic closure.  They do not
grant Scope, Capability, Permit, Tool, Finding, or Graph authority.  A future
trusted compiler may bind one exact profile reference to separately reviewed
execution contracts, but model or agent output can never register a profile.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Annotated, Final, Literal, Self

from pydantic import ConfigDict, Field, ValidationInfo, field_validator, model_validator

from pajin.agentic.models import (
    AgenticStrictModel,
    AnalysisSkillReference,
    PentestSpecialization,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest

SPECIALIST_EXECUTION_PROFILE_API_VERSION: Literal[
    "pajin.dev/specialist-execution-profile/v1alpha1"
] = "pajin.dev/specialist-execution-profile/v1alpha1"

_PROFILE_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-execution-profile/v1"
_CATALOG_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-execution-profile-catalog/v1"
_IDENTIFIER_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_STEP_PATTERN: Final = r"^[a-z0-9][a-z0-9-]{1,79}$"
_THREAT_CLASS_PATTERN: Final = r"^[a-z0-9][a-z0-9.-]{1,79}$"
_CWE_PATTERN: Final = r"^CWE-[1-9][0-9]{0,5}$"
_SEMVER_PATTERN: Final = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
_SHA256_PATTERN: Final = r"^[a-f0-9]{64}$"
_PROFILE_FACTORY_TOKEN: Final = object()
_CATALOG_FACTORY_TOKEN: Final = object()
_RESOLVED_FACTORY_TOKEN: Final = object()

Identifier = Annotated[str, Field(min_length=1, max_length=200, pattern=_IDENTIFIER_PATTERN)]
Semver = Annotated[str, Field(pattern=_SEMVER_PATTERN)]
Sha256 = Annotated[str, Field(pattern=_SHA256_PATTERN)]
DiagnosticStep = Annotated[str, Field(pattern=_STEP_PATTERN)]
ThreatClass = Annotated[str, Field(pattern=_THREAT_CLASS_PATTERN)]
FindingCategory = Annotated[str, Field(pattern=_CWE_PATTERN)]


class SpecialistExecutionProfileError(ValueError):
    """Raised when an inert specialist profile cannot be resolved exactly."""


def _has_exact_runtime_shape(value: object, model_type: type[AgenticStrictModel]) -> bool:
    return (
        type(value) is model_type
        and set(vars(value)) == set(model_type.model_fields)
        and all(_has_exact_wire_runtime_shape(item) for item in vars(value).values())
    )


def _has_exact_wire_runtime_shape(value: object) -> bool:
    if value is None or type(value) in {bool, int, float, str}:
        return True
    if type(value) is PentestSpecialization:
        return True
    if type(value) is tuple:
        return all(_has_exact_wire_runtime_shape(item) for item in value)
    if type(value) is AnalysisSkillReference:
        return _has_exact_runtime_shape(value, AnalysisSkillReference)
    if type(value) is SpecialistExecutionDependency:
        return _has_exact_runtime_shape(value, SpecialistExecutionDependency)
    return False


def _snapshot_has_exact_runtime_shape(
    snapshot: SpecialistExecutionProfileSnapshot,
) -> bool:
    return (
        _has_exact_runtime_shape(snapshot, SpecialistExecutionProfileSnapshot)
        and all(
            _has_exact_runtime_shape(reference, AnalysisSkillReference)
            for reference in (*snapshot.selection_skill_refs, *snapshot.supporting_skill_refs)
        )
        and all(
            _has_exact_runtime_shape(edge, SpecialistExecutionDependency)
            for edge in snapshot.dependency_edges
        )
    )


def _skill_identity_keys(
    references: tuple[AnalysisSkillReference, ...],
) -> tuple[tuple[str, str, str, str, str, str], ...]:
    return tuple(
        (
            reference.skill_id,
            reference.skill_version,
            reference.skill_digest,
            reference.instruction_digest,
            reference.input_schema_digest,
            reference.output_schema_digest,
        )
        for reference in references
    )


def _require_canonical_skill_sets(snapshot: SpecialistExecutionProfileSnapshot) -> None:
    selection_keys = _skill_identity_keys(snapshot.selection_skill_refs)
    supporting_keys = _skill_identity_keys(snapshot.supporting_skill_refs)
    if selection_keys != tuple(sorted(set(selection_keys))):
        raise ValueError(
            "specialist execution selection Skill references must be unique and sorted"
        )
    if supporting_keys != tuple(sorted(set(supporting_keys))):
        raise ValueError(
            "specialist execution supporting Skill references must be unique and sorted"
        )
    if set(selection_keys) & set(supporting_keys):
        raise ValueError("specialist execution selection and supporting Skills must be distinct")


def _require_canonical_closure(snapshot: SpecialistExecutionProfileSnapshot) -> None:
    if len(snapshot.diagnostic_steps) != len(set(snapshot.diagnostic_steps)):
        raise ValueError("specialist execution diagnostic steps must be unique")
    dependency_keys = tuple(
        (edge.predecessor_step, edge.dependent_step, edge.purpose, edge.evidence_type)
        for edge in snapshot.dependency_edges
    )
    if dependency_keys != tuple(sorted(set(dependency_keys))):
        raise ValueError("specialist execution dependencies must be unique and sorted")
    step_positions = {step: index for index, step in enumerate(snapshot.diagnostic_steps)}
    for edge in snapshot.dependency_edges:
        if edge.predecessor_step not in step_positions or edge.dependent_step not in step_positions:
            raise ValueError("specialist execution dependency must reference installed steps")
        if step_positions[edge.predecessor_step] >= step_positions[edge.dependent_step]:
            raise ValueError(
                "specialist execution dependency must point forward in diagnostic order"
            )
    if len(snapshot.promotable_steps) != len(set(snapshot.promotable_steps)):
        raise ValueError("specialist execution promotable steps must be unique")
    expected_promotable_order = tuple(
        step for step in snapshot.diagnostic_steps if step in set(snapshot.promotable_steps)
    )
    if snapshot.promotable_steps != expected_promotable_order:
        raise ValueError("specialist execution promotable steps must preserve diagnostic order")
    if any(step not in step_positions for step in snapshot.promotable_steps):
        raise ValueError("specialist execution promotable steps must be part of the closure")


def _require_canonical_categories(snapshot: SpecialistExecutionProfileSnapshot) -> None:
    if snapshot.required_capability_categories != tuple(
        sorted(set(snapshot.required_capability_categories))
    ):
        raise ValueError(
            "specialist execution required Capability categories must be unique and sorted"
        )
    if snapshot.promotable_finding_categories != tuple(
        sorted(set(snapshot.promotable_finding_categories))
    ):
        raise ValueError(
            "specialist execution promotable Finding categories must be unique and sorted"
        )
    if not set(snapshot.promotable_finding_categories) <= set(
        snapshot.required_capability_categories
    ):
        raise ValueError(
            "promotable Finding categories must be covered by required Capability categories"
        )


def _literal_false(value: object, *, label: str | None) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError(f"{label or 'authority marker'} must be literal false")
    return False


def _literal_true(value: object, *, label: str | None) -> Literal[True]:
    if type(value) is not bool or value is not True:
        raise ValueError(f"{label or 'boundary marker'} must be literal true")
    return True


def _is_mapping_proxy(value: object) -> bool:
    return type(value) is type(MappingProxyType({}))


class SpecialistExecutionDependency(AgenticStrictModel):
    """One explicit forward data dependency inside a diagnostic closure."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    predecessor_step: DiagnosticStep = Field(alias="predecessorStep")
    dependent_step: DiagnosticStep = Field(alias="dependentStep")
    purpose: Identifier
    evidence_type: Identifier = Field(alias="evidenceType")

    @model_validator(mode="after")
    def reject_self_dependency(self) -> Self:
        if self.predecessor_step == self.dependent_step:
            raise ValueError("specialist execution dependency cannot reference one step twice")
        return self


class SpecialistExecutionProfileRef(AgenticStrictModel):
    """Exact ID, version, and digest reference to one installed inert profile."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    profile_id: Identifier = Field(alias="profileId")
    profile_version: Semver = Field(alias="profileVersion")
    profile_digest: Sha256 = Field(alias="profileDigest")


class SpecialistExecutionProfileSnapshot(AgenticStrictModel):
    """Serializable non-authoritative description of one diagnostic closure."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/specialist-execution-profile/v1alpha1"] = Field(
        default=SPECIALIST_EXECUTION_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SpecialistExecutionProfile"] = "SpecialistExecutionProfile"
    profile_id: Identifier = Field(alias="profileId")
    profile_version: Semver = Field(alias="profileVersion")
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    specialization: PentestSpecialization
    threat_class: ThreatClass = Field(alias="threatClass")
    selection_skill_refs: tuple[AnalysisSkillReference, ...] = Field(
        alias="selectionSkillRefs",
        min_length=1,
        max_length=16,
    )
    supporting_skill_refs: tuple[AnalysisSkillReference, ...] = Field(
        default=(),
        alias="supportingSkillRefs",
        max_length=16,
    )
    adapter_implementation_id: Identifier = Field(alias="adapterImplementationId")
    adapter_implementation_digest: Sha256 = Field(alias="adapterImplementationDigest")
    adapter_catalog_digest: Sha256 = Field(alias="adapterCatalogDigest")
    diagnostic_steps: tuple[DiagnosticStep, ...] = Field(
        alias="diagnosticSteps",
        min_length=1,
        max_length=16,
    )
    dependency_edges: tuple[SpecialistExecutionDependency, ...] = Field(
        default=(),
        alias="dependencyEdges",
        max_length=32,
    )
    promotable_steps: tuple[DiagnosticStep, ...] = Field(
        alias="promotableSteps",
        min_length=1,
        max_length=16,
    )
    required_capability_categories: tuple[FindingCategory, ...] = Field(
        alias="requiredCapabilityCategories",
        min_length=1,
        max_length=16,
    )
    promotable_finding_categories: tuple[FindingCategory, ...] = Field(
        alias="promotableFindingCategories",
        min_length=1,
        max_length=16,
    )
    state: Literal["registered-inert"] = "registered-inert"
    execution_binding: Literal["unbound"] = Field(
        default="unbound",
        alias="executionBinding",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    fresh_approval_required: Literal[True] = Field(
        default=True,
        alias="freshApprovalRequired",
    )
    independent_validation_required: Literal[True] = Field(
        default=True,
        alias="independentValidationRequired",
    )
    caller_executable_input: Literal[False] = Field(
        default=False,
        alias="callerExecutableInput",
    )
    scope_authority: Literal[False] = Field(default=False, alias="scopeAuthority")
    capability_authority: Literal[False] = Field(default=False, alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(default=False, alias="permitAuthority")
    gateway_authority: Literal[False] = Field(default=False, alias="gatewayAuthority")
    worker_authority: Literal[False] = Field(default=False, alias="workerAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    evidence_authority: Literal[False] = Field(default=False, alias="evidenceAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_admission_authority: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthority",
    )
    report_authority: Literal[False] = Field(default=False, alias="reportAuthority")
    skill_lifecycle_upgrade_authority: Literal[False] = Field(
        default=False,
        alias="skillLifecycleUpgradeAuthority",
    )

    @field_validator(
        "caller_executable_input",
        "runtime_support_asserted",
        "scope_authority",
        "capability_authority",
        "permit_authority",
        "gateway_authority",
        "worker_authority",
        "execution_authority",
        "evidence_authority",
        "finding_authority",
        "graph_admission_authority",
        "report_authority",
        "skill_lifecycle_upgrade_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @field_validator(
        "fresh_approval_required",
        "independent_validation_required",
        mode="before",
    )
    @classmethod
    def require_true_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_true(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_profile_identity(self) -> Self:
        _require_canonical_skill_sets(self)
        _require_canonical_closure(self)
        _require_canonical_categories(self)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_digest"},
        )
        digest = discovery_digest(_PROFILE_DIGEST_DOMAIN, material)
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("specialist execution profile digest differs")
        object.__setattr__(self, "profile_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Specialist Execution Profile",
            max_bytes=64 * 1024,
        )
        return self

    def reference(self) -> SpecialistExecutionProfileRef:
        """Return a detached exact reference with no execution authority."""

        canonical = SpecialistExecutionProfileSnapshot.model_validate(
            self.model_dump(mode="json", by_alias=True)
        )
        return SpecialistExecutionProfileRef(
            profileId=canonical.profile_id,
            profileVersion=canonical.profile_version,
            profileDigest=canonical.profile_digest,
        )


@dataclass(frozen=True, slots=True)
class _CodeOwnedSpecialistExecutionProfile:
    snapshot: SpecialistExecutionProfileSnapshot
    _factory_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self) is not _CodeOwnedSpecialistExecutionProfile
            or self._factory_token is not _PROFILE_FACTORY_TOKEN
            or not _snapshot_has_exact_runtime_shape(self.snapshot)
        ):
            raise TypeError("specialist execution profile requires its code-owned factory")
        try:
            canonical = SpecialistExecutionProfileSnapshot.model_validate(
                self.snapshot.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise SpecialistExecutionProfileError(
                "specialist execution profile is not canonical"
            ) from exc
        if canonical != self.snapshot:
            raise SpecialistExecutionProfileError(
                "specialist execution profile differs after strict reload"
            )


def _new_code_owned_specialist_execution_profile(
    snapshot: SpecialistExecutionProfileSnapshot,
) -> _CodeOwnedSpecialistExecutionProfile:
    if not _snapshot_has_exact_runtime_shape(snapshot):
        raise SpecialistExecutionProfileError(
            "specialist execution profile runtime shape is not canonical"
        )
    canonical = SpecialistExecutionProfileSnapshot.model_validate(
        snapshot.model_dump(mode="json", by_alias=True)
    )
    if type(snapshot) is not SpecialistExecutionProfileSnapshot or canonical != snapshot:
        raise SpecialistExecutionProfileError(
            "specialist execution profile differs after strict reload"
        )
    return _CodeOwnedSpecialistExecutionProfile(
        snapshot=canonical,
        _factory_token=_PROFILE_FACTORY_TOKEN,
    )


def _catalog_digest(
    profiles: tuple[_CodeOwnedSpecialistExecutionProfile, ...],
) -> str:
    return discovery_digest(
        _CATALOG_DIGEST_DOMAIN,
        {
            "profiles": [
                profile.snapshot.model_dump(mode="json", by_alias=True) for profile in profiles
            ],
            "authority": {
                "scope": False,
                "capability": False,
                "permit": False,
                "gateway": False,
                "worker": False,
                "execution": False,
                "evidence": False,
                "finding": False,
                "graphAdmission": False,
                "report": False,
            },
        },
    )


@dataclass(frozen=True, slots=True)
class ResolvedSpecialistExecutionProfile:
    """Registry-minted handle to one exact inert profile snapshot."""

    registry_digest: str
    _snapshot: SpecialistExecutionProfileSnapshot = field(repr=False)
    _descriptor: _CodeOwnedSpecialistExecutionProfile = field(repr=False)
    _catalog: SpecialistExecutionProfileCatalog = field(repr=False)
    _factory_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self) is not ResolvedSpecialistExecutionProfile
            or self._factory_token is not _RESOLVED_FACTORY_TOKEN
        ):
            raise TypeError("resolved specialist execution profile requires catalog resolution")
        self._require_current()

    def _require_current(self) -> None:
        self._catalog._require_resolved(
            registry_digest=self.registry_digest,
            snapshot=self._snapshot,
            descriptor=self._descriptor,
        )

    def reference(self) -> SpecialistExecutionProfileRef:
        """Return a strict-reloaded detached reference."""

        self._require_current()
        return self._snapshot.reference()

    def snapshot(self) -> SpecialistExecutionProfileSnapshot:
        """Return detached inert metadata; it cannot authorize execution."""

        self._require_current()
        return SpecialistExecutionProfileSnapshot.model_validate(
            self._snapshot.model_dump(mode="json", by_alias=True)
        )

    @property
    def profile_id(self) -> str:
        self._require_current()
        return self._snapshot.profile_id

    @property
    def profile_version(self) -> str:
        self._require_current()
        return self._snapshot.profile_version

    @property
    def profile_digest(self) -> str:
        self._require_current()
        return self._snapshot.profile_digest

    @property
    def specialization(self) -> PentestSpecialization:
        self._require_current()
        return self._snapshot.specialization

    @property
    def threat_class(self) -> str:
        self._require_current()
        return self._snapshot.threat_class

    @property
    def diagnostic_steps(self) -> tuple[str, ...]:
        self._require_current()
        return self._snapshot.diagnostic_steps

    @property
    def dependency_edges(self) -> tuple[SpecialistExecutionDependency, ...]:
        self._require_current()
        return tuple(
            SpecialistExecutionDependency.model_validate(
                edge.model_dump(mode="json", by_alias=True)
            )
            for edge in self._snapshot.dependency_edges
        )

    @property
    def promotable_steps(self) -> tuple[str, ...]:
        self._require_current()
        return self._snapshot.promotable_steps

    @property
    def required_capability_categories(self) -> tuple[str, ...]:
        self._require_current()
        return self._snapshot.required_capability_categories

    @property
    def promotable_finding_categories(self) -> tuple[str, ...]:
        self._require_current()
        return self._snapshot.promotable_finding_categories


class SpecialistExecutionProfileCatalog:
    """Closed exact-key catalog with no registration or latest-version path."""

    __slots__ = ("__entries", "__profiles", "__registry_digest")
    __entries: Mapping[tuple[str, str, str], _CodeOwnedSpecialistExecutionProfile]
    __profiles: tuple[_CodeOwnedSpecialistExecutionProfile, ...]
    __registry_digest: str

    def __init__(
        self,
        *,
        _profiles: tuple[_CodeOwnedSpecialistExecutionProfile, ...],
        _factory_token: object | None = None,
    ) -> None:
        if (
            type(self) is not SpecialistExecutionProfileCatalog
            or _factory_token is not _CATALOG_FACTORY_TOKEN
        ):
            raise TypeError("specialist execution profile catalog requires its code-owned factory")
        if not _profiles:
            raise SpecialistExecutionProfileError("specialist execution profile catalog is empty")
        entries: dict[tuple[str, str, str], _CodeOwnedSpecialistExecutionProfile] = {}
        identity_pairs: set[tuple[str, str]] = set()
        digests: set[str] = set()
        for profile in _profiles:
            self._require_code_owned_profile(profile)
            snapshot = profile.snapshot
            reference = snapshot.reference()
            key = (
                reference.profile_id,
                reference.profile_version,
                reference.profile_digest,
            )
            identity_pair = (reference.profile_id, reference.profile_version)
            if (
                key in entries
                or identity_pair in identity_pairs
                or reference.profile_digest in digests
            ):
                raise SpecialistExecutionProfileError(
                    "specialist execution profile catalog contains a duplicate identity"
                )
            entries[key] = profile
            identity_pairs.add(identity_pair)
            digests.add(reference.profile_digest)
        profiles = tuple(
            sorted(
                entries.values(),
                key=lambda item: (
                    item.snapshot.profile_id,
                    item.snapshot.profile_version,
                    item.snapshot.profile_digest,
                ),
            )
        )
        object.__setattr__(
            self,
            "_SpecialistExecutionProfileCatalog__entries",
            MappingProxyType(entries),
        )
        object.__setattr__(
            self,
            "_SpecialistExecutionProfileCatalog__profiles",
            profiles,
        )
        object.__setattr__(
            self,
            "_SpecialistExecutionProfileCatalog__registry_digest",
            _catalog_digest(profiles),
        )

    @property
    def registry_digest(self) -> str:
        self._require_current()
        return self.__registry_digest

    def references(self) -> tuple[SpecialistExecutionProfileRef, ...]:
        """Return detached exact references in canonical order."""

        self._require_current()
        return tuple(profile.snapshot.reference() for profile in self.__profiles)

    def resolve(
        self,
        reference: SpecialistExecutionProfileRef,
    ) -> ResolvedSpecialistExecutionProfile:
        """Resolve only one exact ID, version, and digest reference."""

        self._require_current()
        canonical = self._canonical_reference(reference)
        try:
            profile = self.__entries[
                (
                    canonical.profile_id,
                    canonical.profile_version,
                    canonical.profile_digest,
                )
            ]
        except KeyError as exc:
            raise SpecialistExecutionProfileError(
                "specialist execution profile reference is not installed"
            ) from exc
        if profile.snapshot.reference() != canonical:
            raise SpecialistExecutionProfileError(
                "specialist execution profile reference differs from the catalog"
            )
        return self._resolved(profile)

    def reload_snapshot(
        self,
        snapshot: SpecialistExecutionProfileSnapshot,
    ) -> ResolvedSpecialistExecutionProfile:
        """Strict-reload serialized inert metadata and match the installed identity."""

        self._require_current()
        if not _snapshot_has_exact_runtime_shape(snapshot):
            raise SpecialistExecutionProfileError(
                "specialist execution profile snapshot runtime shape is not canonical"
            )
        try:
            canonical = SpecialistExecutionProfileSnapshot.model_validate(
                snapshot.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise SpecialistExecutionProfileError(
                "specialist execution profile snapshot failed strict reload"
            ) from exc
        if canonical != snapshot:
            raise SpecialistExecutionProfileError(
                "specialist execution profile snapshot differs after strict reload"
            )
        resolved = self.resolve(canonical.reference())
        if resolved.snapshot() != canonical:
            raise SpecialistExecutionProfileError(
                "specialist execution profile snapshot differs from the catalog"
            )
        return resolved

    def _resolved(
        self,
        profile: _CodeOwnedSpecialistExecutionProfile,
    ) -> ResolvedSpecialistExecutionProfile:
        snapshot = SpecialistExecutionProfileSnapshot.model_validate(
            profile.snapshot.model_dump(mode="json", by_alias=True)
        )
        return ResolvedSpecialistExecutionProfile(
            registry_digest=self.__registry_digest,
            _snapshot=snapshot,
            _descriptor=profile,
            _catalog=self,
            _factory_token=_RESOLVED_FACTORY_TOKEN,
        )

    def _require_resolved(
        self,
        *,
        registry_digest: str,
        snapshot: SpecialistExecutionProfileSnapshot,
        descriptor: _CodeOwnedSpecialistExecutionProfile,
    ) -> None:
        self._require_current()
        if registry_digest != self.__registry_digest:
            raise SpecialistExecutionProfileError(
                "resolved specialist execution profile registry identity changed"
            )
        self._require_code_owned_profile(descriptor)
        reference = descriptor.snapshot.reference()
        key = (
            reference.profile_id,
            reference.profile_version,
            reference.profile_digest,
        )
        if self.__entries.get(key) is not descriptor:
            raise SpecialistExecutionProfileError(
                "resolved specialist execution profile is not installed"
            )
        if not _snapshot_has_exact_runtime_shape(snapshot):
            raise SpecialistExecutionProfileError(
                "resolved specialist execution profile runtime shape changed"
            )
        try:
            canonical = SpecialistExecutionProfileSnapshot.model_validate(
                snapshot.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise SpecialistExecutionProfileError(
                "resolved specialist execution profile failed strict reload"
            ) from exc
        if canonical != snapshot or canonical != descriptor.snapshot:
            raise SpecialistExecutionProfileError(
                "resolved specialist execution profile identity changed"
            )

    def _require_current(self) -> None:
        if type(self) is not SpecialistExecutionProfileCatalog:
            raise SpecialistExecutionProfileError(
                "specialist execution profile catalog type changed"
            )
        profiles = self.__profiles
        if (
            not _is_mapping_proxy(self.__entries)
            or type(profiles) is not tuple
            or len(self.__entries) != len(profiles)
        ):
            raise SpecialistExecutionProfileError(
                "specialist execution profile catalog identity changed"
            )
        expected_order = tuple(
            sorted(
                profiles,
                key=lambda item: (
                    item.snapshot.profile_id,
                    item.snapshot.profile_version,
                    item.snapshot.profile_digest,
                ),
            )
        )
        if expected_order != profiles:
            raise SpecialistExecutionProfileError(
                "specialist execution profile catalog order changed"
            )
        for profile in profiles:
            self._require_code_owned_profile(profile)
            reference = profile.snapshot.reference()
            key = (
                reference.profile_id,
                reference.profile_version,
                reference.profile_digest,
            )
            if self.__entries.get(key) is not profile:
                raise SpecialistExecutionProfileError(
                    "specialist execution profile catalog identity changed"
                )
        if _catalog_digest(profiles) != self.__registry_digest:
            raise SpecialistExecutionProfileError(
                "specialist execution profile catalog digest changed"
            )

    @staticmethod
    def _canonical_reference(
        reference: SpecialistExecutionProfileRef,
    ) -> SpecialistExecutionProfileRef:
        if not _has_exact_runtime_shape(reference, SpecialistExecutionProfileRef):
            raise SpecialistExecutionProfileError(
                "specialist execution profile reference runtime shape is not canonical"
            )
        try:
            canonical = SpecialistExecutionProfileRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise SpecialistExecutionProfileError(
                "specialist execution profile reference failed strict reload"
            ) from exc
        if canonical != reference:
            raise SpecialistExecutionProfileError(
                "specialist execution profile reference differs after strict reload"
            )
        return canonical

    @staticmethod
    def _require_code_owned_profile(
        profile: _CodeOwnedSpecialistExecutionProfile,
    ) -> None:
        if (
            type(profile) is not _CodeOwnedSpecialistExecutionProfile
            or profile._factory_token is not _PROFILE_FACTORY_TOKEN
            or not _snapshot_has_exact_runtime_shape(profile.snapshot)
        ):
            raise SpecialistExecutionProfileError("specialist execution profile is not code-owned")
        try:
            canonical = SpecialistExecutionProfileSnapshot.model_validate(
                profile.snapshot.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise SpecialistExecutionProfileError(
                "specialist execution profile failed strict reload"
            ) from exc
        if canonical != profile.snapshot:
            raise SpecialistExecutionProfileError(
                "specialist execution profile differs after strict reload"
            )


def _new_specialist_execution_profile_catalog(
    profiles: tuple[_CodeOwnedSpecialistExecutionProfile, ...],
) -> SpecialistExecutionProfileCatalog:
    return SpecialistExecutionProfileCatalog(
        _profiles=profiles,
        _factory_token=_CATALOG_FACTORY_TOKEN,
    )


__all__ = [
    "SPECIALIST_EXECUTION_PROFILE_API_VERSION",
    "ResolvedSpecialistExecutionProfile",
    "SpecialistExecutionDependency",
    "SpecialistExecutionProfileCatalog",
    "SpecialistExecutionProfileError",
    "SpecialistExecutionProfileRef",
    "SpecialistExecutionProfileSnapshot",
]
