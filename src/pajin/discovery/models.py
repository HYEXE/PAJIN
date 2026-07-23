"""Versioned, non-executable contracts for evidence-bound attack surfaces."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import PurePosixPath
from re import fullmatch
from typing import Annotated, ClassVar, Literal

from pydantic import Field, TypeAdapter, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.domain.models import StrictModel
from pajin.policy.scope import normalize_target_url

DISCOVERY_API_VERSION: Literal["pajin.dev/discovery/v1alpha1"] = (
    "pajin.dev/discovery/v1alpha1"
)

_MAX_ARTIFACT_BYTES = 64 * 1024
_MAX_SURFACE_SET_BYTES = 4 * 1024 * 1024
_MAX_EVIDENCE_REFERENCES = 50
_MAX_OBSERVATIONS = 1_000
_MAX_SURFACES = 500

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_CampaignIdentifier = Annotated[
    str,
    Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$"),
]
_PortableIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Confidence = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]

_OBSERVATION_ID_PATTERN = r"^surface-observation_[a-f0-9]{64}$"
_SURFACE_ID_PATTERN = r"^attack-surface_[a-f0-9]{64}$"
_SURFACE_SET_ID_PATTERN = r"^attack-surface-set_[a-f0-9]{64}$"


def _normalize_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset or Z")
    return value.astimezone(UTC)


def _utc_wire(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _require_safe_text(value: str, *, label: str) -> str:
    if value != value.strip():
        raise ValueError(f"{label} cannot contain surrounding whitespace")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{label} cannot contain control characters")
    return value


def _reference_sort_key(reference: SurfaceEvidenceReference) -> tuple[str, str, str]:
    return (reference.reference, reference.sha256, reference.media_type)


def _observation_identity_payload(observation: SurfaceObservation) -> dict[str, object]:
    return {
        "campaign": observation.campaign,
        "runId": observation.run_id,
        "sourceRootDigest": observation.source_root_digest,
        "targetId": observation.target_id,
        "requestId": observation.request_id,
        "requestTarget": observation.request_target,
        "toolId": observation.tool_id,
        "sourceRequestDigest": observation.source_request_digest,
        "sourceResultDigest": observation.source_result_digest,
        "locator": observation.locator.model_dump(mode="json"),
        "evidence": [item.model_dump(mode="json") for item in observation.evidence],
        "observedAt": _utc_wire(observation.observed_at),
    }


def _surface_identity_payload(surface: AttackSurface) -> dict[str, object]:
    return {
        "campaign": surface.campaign,
        "targetId": surface.target_id,
        "locator": surface.locator.model_dump(mode="json"),
    }


def _surface_set_identity_payload(surface_set: AttackSurfaceSet) -> dict[str, object]:
    return {
        "campaign": surface_set.campaign,
        "runId": surface_set.run_id,
        "sourceRootDigest": surface_set.source_root_digest,
        "observations": [
            observation.model_dump(mode="json") for observation in surface_set.observations
        ],
        "surfaces": [surface.model_dump(mode="json") for surface in surface_set.surfaces],
        "generatedAt": _utc_wire(surface_set.generated_at),
    }


class DiscoveryArtifactModel(StrictModel):
    """Base class for bounded, versioned discovery artifacts."""

    canonical_byte_limit: ClassVar[int] = _MAX_ARTIFACT_BYTES
    api_version: Literal["pajin.dev/discovery/v1alpha1"] = Field(
        default=DISCOVERY_API_VERSION,
        alias="apiVersion",
    )

    @model_validator(mode="after")
    def require_bounded_canonical_json(self) -> DiscoveryArtifactModel:
        _require_bounded_discovery_artifact(self)
        return self


def _require_bounded_discovery_artifact(artifact: DiscoveryArtifactModel) -> None:
    canonical_json_bytes(
        artifact.model_dump(mode="json", by_alias=True),
        label=artifact.__class__.__name__,
        max_bytes=artifact.canonical_byte_limit,
    )


class HTTPSurfaceLocator(StrictModel):
    """Canonical identity of one concrete HTTP operation."""

    kind: Literal["http-endpoint"] = "http-endpoint"
    url: str = Field(min_length=1, max_length=2_000)
    method: str = Field(min_length=1, max_length=20, pattern=r"^[A-Z0-9!#$%&'*+.^_`|~-]+$")

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        return normalize_target_url(value)

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value


class ToolInterfaceSurfaceLocator(StrictModel):
    """Canonical identity of one registered, versioned Tool interface."""

    kind: Literal["tool-interface"] = "tool-interface"
    registry_id: _Identifier
    tool_id: _Identifier
    tool_version: str = Field(min_length=1, max_length=100)
    input_schema_digest: _Sha256

    @field_validator("tool_version")
    @classmethod
    def validate_tool_version(cls, value: str) -> str:
        return _require_safe_text(value, label="Tool version")


SurfaceLocator = Annotated[
    HTTPSurfaceLocator | ToolInterfaceSurfaceLocator,
    Field(discriminator="kind"),
]
_SURFACE_LOCATOR_ADAPTER: TypeAdapter[SurfaceLocator] = TypeAdapter(SurfaceLocator)


class SurfaceEvidenceReference(StrictModel):
    """Digest-bound reference to immutable evidence in the source Run."""

    reference: str = Field(min_length=1, max_length=2_000)
    sha256: _Sha256
    media_type: str = Field(default="application/json", min_length=1, max_length=100)

    @field_validator("reference")
    @classmethod
    def validate_reference(cls, value: str) -> str:
        value = _require_safe_text(value, label="Evidence reference")
        if "\\" in value:
            raise ValueError("Evidence reference must use portable forward slashes")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("Evidence reference must be a normalized relative path")
        if path.as_posix() != value:
            raise ValueError("Evidence reference must be a normalized relative path")
        return value

    @field_validator("media_type")
    @classmethod
    def validate_media_type(cls, value: str) -> str:
        return _require_safe_text(value, label="Evidence media type")


class SurfaceObservation(DiscoveryArtifactModel):
    """Unprivileged observation bound to one exact Tool request and result."""

    kind: Literal["SurfaceObservation"] = "SurfaceObservation"
    observation_id: str = ""
    campaign: _CampaignIdentifier
    run_id: _Identifier
    source_root_digest: _Sha256
    target_id: _Identifier
    request_id: _PortableIdentifier
    request_target: str = Field(min_length=1, max_length=2_000)
    tool_id: _Identifier
    source_request_digest: _Sha256
    source_result_digest: _Sha256
    locator: SurfaceLocator
    evidence: list[SurfaceEvidenceReference] = Field(
        min_length=1,
        max_length=_MAX_EVIDENCE_REFERENCES,
    )
    observed_at: datetime

    @field_validator("request_target")
    @classmethod
    def validate_request_target(cls, value: str) -> str:
        return _require_safe_text(value, label="Request target")

    @field_validator("observed_at")
    @classmethod
    def normalize_observed_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="observed_at")

    @model_validator(mode="after")
    def validate_observation_identity(self) -> SurfaceObservation:
        ordered = sorted(self.evidence, key=_reference_sort_key)
        if self.evidence != ordered:
            raise ValueError("Surface observation evidence must be canonically sorted")
        references = [reference.reference for reference in self.evidence]
        if len(references) != len(set(references)):
            raise ValueError("Surface observation evidence references must be unique")
        expected = "surface-observation_" + discovery_digest(
            "pajin.discovery.surface-observation/v1",
            _observation_identity_payload(self),
        )
        if not self.observation_id:
            self.observation_id = expected
        elif self.observation_id != expected:
            raise ValueError("Surface observation ID differs from canonical authority")
        if fullmatch(_OBSERVATION_ID_PATTERN, self.observation_id) is None:
            raise ValueError("Surface observation ID is malformed")
        _require_bounded_discovery_artifact(self)
        return self


class AttackSurface(DiscoveryArtifactModel):
    """Canonical surface identity with evidence-bound observation lineage."""

    kind: Literal["AttackSurface"] = "AttackSurface"
    surface_id: str = ""
    campaign: _CampaignIdentifier
    target_id: _Identifier
    locator: SurfaceLocator
    observation_ids: list[str] = Field(min_length=1, max_length=_MAX_OBSERVATIONS)
    confidence: _Confidence
    first_observed_at: datetime
    last_observed_at: datetime

    @field_validator("observation_ids")
    @classmethod
    def validate_observation_ids(cls, values: list[str]) -> list[str]:
        if any(fullmatch(_OBSERVATION_ID_PATTERN, value) is None for value in values):
            raise ValueError("Attack Surface contains a malformed observation ID")
        if values != sorted(values):
            raise ValueError("Attack Surface observation IDs must be canonically sorted")
        if len(values) != len(set(values)):
            raise ValueError("Attack Surface observation IDs must be unique")
        return values

    @field_validator("first_observed_at", "last_observed_at")
    @classmethod
    def normalize_observation_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Attack Surface observation time")

    @model_validator(mode="after")
    def validate_surface_identity(self) -> AttackSurface:
        if self.first_observed_at > self.last_observed_at:
            raise ValueError("Attack Surface first observation cannot follow the last observation")
        expected = "attack-surface_" + discovery_digest(
            "pajin.discovery.attack-surface/v1",
            _surface_identity_payload(self),
        )
        if not self.surface_id:
            self.surface_id = expected
        elif self.surface_id != expected:
            raise ValueError("Attack Surface ID differs from canonical identity")
        if fullmatch(_SURFACE_ID_PATTERN, self.surface_id) is None:
            raise ValueError("Attack Surface ID is malformed")
        _require_bounded_discovery_artifact(self)
        return self


class AttackSurfaceSet(DiscoveryArtifactModel):
    """Versioned snapshot of observations and their canonical admitted surfaces."""

    canonical_byte_limit: ClassVar[int] = _MAX_SURFACE_SET_BYTES
    kind: Literal["AttackSurfaceSet"] = "AttackSurfaceSet"
    surface_set_id: str = ""
    campaign: _CampaignIdentifier
    run_id: _Identifier
    source_root_digest: _Sha256
    observations: list[SurfaceObservation] = Field(
        default_factory=list,
        max_length=_MAX_OBSERVATIONS,
    )
    surfaces: list[AttackSurface] = Field(default_factory=list, max_length=_MAX_SURFACES)
    generated_at: datetime

    @field_validator("generated_at")
    @classmethod
    def normalize_generated_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="generated_at")

    @model_validator(mode="after")
    def validate_snapshot_authority(self) -> AttackSurfaceSet:
        self._require_canonical_order_and_uniqueness()
        observation_by_id = {item.observation_id: item for item in self.observations}
        references = Counter(
            observation_id
            for surface in self.surfaces
            for observation_id in surface.observation_ids
        )
        incorrectly_linked = set(references) != set(observation_by_id) or any(
            count != 1 for count in references.values()
        )
        if incorrectly_linked:
            raise ValueError(
                "Each Surface observation must be referenced by exactly one Attack Surface"
            )
        for observation in self.observations:
            if observation.campaign != self.campaign or observation.run_id != self.run_id:
                raise ValueError("Surface observation belongs to another Campaign or Run")
            if observation.source_root_digest != self.source_root_digest:
                raise ValueError("Surface observation belongs to another source root")
            if observation.observed_at > self.generated_at:
                raise ValueError("Surface Set cannot predate an included observation")
        for surface in self.surfaces:
            self._validate_surface_lineage(surface, observation_by_id)
        expected = "attack-surface-set_" + discovery_digest(
            "pajin.discovery.attack-surface-set/v1",
            _surface_set_identity_payload(self),
        )
        if not self.surface_set_id:
            self.surface_set_id = expected
        elif self.surface_set_id != expected:
            raise ValueError("Attack Surface Set ID differs from canonical authority")
        if fullmatch(_SURFACE_SET_ID_PATTERN, self.surface_set_id) is None:
            raise ValueError("Attack Surface Set ID is malformed")
        _require_bounded_discovery_artifact(self)
        return self

    def _require_canonical_order_and_uniqueness(self) -> None:
        observation_ids = [item.observation_id for item in self.observations]
        surface_ids = [item.surface_id for item in self.surfaces]
        if observation_ids != sorted(observation_ids):
            raise ValueError("Surface observations must be canonically sorted")
        if surface_ids != sorted(surface_ids):
            raise ValueError("Attack Surfaces must be canonically sorted")
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("Surface observation IDs must be unique")
        if len(surface_ids) != len(set(surface_ids)):
            raise ValueError("Attack Surface IDs must be unique")

    def _validate_surface_lineage(
        self,
        surface: AttackSurface,
        observation_by_id: Mapping[str, SurfaceObservation],
    ) -> None:
        if surface.campaign != self.campaign:
            raise ValueError("Attack Surface belongs to another Campaign")
        observations = [observation_by_id[item] for item in surface.observation_ids]
        if any(observation.target_id != surface.target_id for observation in observations):
            raise ValueError("Attack Surface target differs from its observations")
        if any(observation.locator != surface.locator for observation in observations):
            raise ValueError("Attack Surface locator differs from its observations")
        observed_times = [observation.observed_at for observation in observations]
        if surface.first_observed_at != min(observed_times):
            raise ValueError("Attack Surface first observation time differs from its lineage")
        if surface.last_observed_at != max(observed_times):
            raise ValueError("Attack Surface last observation time differs from its lineage")


def http_surface_locator(*, url: str, method: str) -> HTTPSurfaceLocator:
    """Build one canonical HTTP locator."""

    return HTTPSurfaceLocator(url=url, method=method)


def tool_interface_surface_locator(
    *,
    registry_id: str,
    tool_id: str,
    tool_version: str,
    input_schema_digest: str,
) -> ToolInterfaceSurfaceLocator:
    """Build one canonical Tool-interface locator."""

    return ToolInterfaceSurfaceLocator(
        registry_id=registry_id,
        tool_id=tool_id,
        tool_version=tool_version,
        input_schema_digest=input_schema_digest,
    )


def surface_observation(
    *,
    campaign: str,
    run_id: str,
    source_root_digest: str,
    target_id: str,
    request_id: str,
    request_target: str,
    tool_id: str,
    source_request_digest: str,
    source_result_digest: str,
    locator: SurfaceLocator | Mapping[str, object],
    evidence: list[SurfaceEvidenceReference | Mapping[str, object]],
    observed_at: datetime,
) -> SurfaceObservation:
    """Build an observation after normalizing locator and evidence order."""

    canonical_locator = _SURFACE_LOCATOR_ADAPTER.validate_python(locator)
    canonical_evidence = [SurfaceEvidenceReference.model_validate(item) for item in evidence]
    return SurfaceObservation(
        campaign=campaign,
        run_id=run_id,
        source_root_digest=source_root_digest,
        target_id=target_id,
        request_id=request_id,
        request_target=request_target,
        tool_id=tool_id,
        source_request_digest=source_request_digest,
        source_result_digest=source_result_digest,
        locator=canonical_locator,
        evidence=sorted(canonical_evidence, key=_reference_sort_key),
        observed_at=observed_at,
    )


def attack_surface(
    *,
    campaign: str,
    target_id: str,
    locator: SurfaceLocator | Mapping[str, object],
    observations: list[SurfaceObservation],
    confidence: float,
) -> AttackSurface:
    """Build one stable Surface identity from exact observations."""

    if not observations:
        raise ValueError("Attack Surface requires at least one observation")
    canonical_locator = _SURFACE_LOCATOR_ADAPTER.validate_python(locator)
    if any(observation.campaign != campaign for observation in observations):
        raise ValueError("Attack Surface observations belong to another Campaign")
    if any(observation.target_id != target_id for observation in observations):
        raise ValueError("Attack Surface target differs from its observations")
    if any(observation.locator != canonical_locator for observation in observations):
        raise ValueError("Attack Surface locator differs from its observations")
    observation_ids = sorted(observation.observation_id for observation in observations)
    times = [observation.observed_at for observation in observations]
    return AttackSurface(
        campaign=campaign,
        target_id=target_id,
        locator=canonical_locator,
        observation_ids=observation_ids,
        confidence=confidence,
        first_observed_at=min(times),
        last_observed_at=max(times),
    )


def attack_surface_set(
    *,
    campaign: str,
    run_id: str,
    source_root_digest: str,
    observations: list[SurfaceObservation],
    surfaces: list[AttackSurface],
    generated_at: datetime,
) -> AttackSurfaceSet:
    """Build a canonically ordered Surface Set snapshot."""

    return AttackSurfaceSet(
        campaign=campaign,
        run_id=run_id,
        source_root_digest=source_root_digest,
        observations=sorted(observations, key=lambda item: item.observation_id),
        surfaces=sorted(surfaces, key=lambda item: item.surface_id),
        generated_at=generated_at,
    )
