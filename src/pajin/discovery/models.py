"""Versioned, non-executable contracts for evidence-bound attack surfaces."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import PurePosixPath
from re import fullmatch, sub
from typing import Annotated, ClassVar, Literal
from urllib.parse import urlsplit, urlunsplit

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
_ROUTE_PARAMETER_PATTERN = r"\{([A-Za-z_][A-Za-z0-9_.-]{0,99})\}"
_ROUTE_LITERAL_SEGMENT_PATTERN = r"(?:[A-Za-z0-9._~!$&'()+,;=:@-]|%[0-9A-F]{2})+"
_MEDIA_TYPE_PATTERN = r"^[a-z0-9!#$&^_.+*-]+/[a-z0-9!#$&^_.+*-]+$"
_HTTP_AUTH_SCHEME_PATTERN = r"^[A-Za-z][A-Za-z0-9+.-]{0,99}$"


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


class HTTPRouteSurfaceLocator(StrictModel):
    """Non-executable HTTP route template declared by a bounded schema."""

    kind: Literal["http-route"] = "http-route"
    base_url: str = Field(min_length=1, max_length=2_000)
    path_template: str = Field(min_length=1, max_length=2_000)
    method: str = Field(min_length=1, max_length=20, pattern=r"^[A-Z0-9!#$%&'*+.^_`|~-]+$")
    request_content_types: tuple[str, ...] = Field(default=(), max_length=32)
    response_content_types: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("base_url")
    @classmethod
    def normalize_base_url(cls, value: str) -> str:
        normalized = normalize_target_url(value)
        parsed = urlsplit(normalized)
        if parsed.query:
            raise ValueError("HTTP route base URL cannot contain a query")
        path = parsed.path.rstrip("/") or "/"
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))

    @field_validator("path_template")
    @classmethod
    def validate_path_template(cls, value: str) -> str:
        if value != value.strip() or not value.startswith("/"):
            raise ValueError("HTTP route template must be an absolute path")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise ValueError("HTTP route template cannot contain control characters")
        if any(character in value for character in ("\\", "?", "#")):
            raise ValueError("HTTP route template contains an ambiguous delimiter")
        if value == "/":
            return value
        segments = value[1:].split("/")
        if any(not segment for segment in segments):
            raise ValueError("HTTP route template cannot contain an empty segment")
        parameters: list[str] = []
        for segment in segments:
            parameter = fullmatch(_ROUTE_PARAMETER_PATTERN, segment)
            if parameter is not None:
                parameters.append(parameter.group(1))
                continue
            if "{" in segment or "}" in segment:
                raise ValueError("HTTP route parameters must occupy one complete segment")
            if fullmatch(_ROUTE_LITERAL_SEGMENT_PATTERN, segment) is None:
                raise ValueError("HTTP route literal segment is not canonical")
        if len(parameters) != len(set(parameters)):
            raise ValueError("HTTP route parameter names must be unique")
        rendered = sub(_ROUTE_PARAMETER_PATTERN, "pajin-route-parameter", value)
        normalized = normalize_target_url(f"https://route.invalid{rendered}")
        if urlsplit(normalized).path != rendered:
            raise ValueError("HTTP route template is not canonically encoded")
        return value

    @field_validator("method", mode="before")
    @classmethod
    def normalize_route_method(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @field_validator(
        "request_content_types",
        "response_content_types",
        mode="before",
    )
    @classmethod
    def normalize_content_types(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            raise ValueError("HTTP route content types must be a list or tuple")
        normalized: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError("HTTP route content type must be text")
            media_type = item.strip().lower()
            wildcard_is_valid = (
                "*" not in media_type
                or media_type == "*/*"
                or (media_type.count("*") == 1 and media_type.endswith("/*"))
            )
            if (
                item != item.strip()
                or fullmatch(_MEDIA_TYPE_PATTERN, media_type) is None
                or not wildcard_is_valid
            ):
                raise ValueError("HTTP route content type is invalid")
            normalized.append(media_type)
        if normalized != sorted(set(normalized)):
            raise ValueError("HTTP route content types must be unique and sorted")
        return tuple(normalized)


class HTTPAuthenticationScheme(StrictModel):
    """Non-secret identity of one referenced OpenAPI authentication scheme."""

    scheme_id: _PortableIdentifier
    scheme_type: Literal["apiKey", "http", "oauth2", "openIdConnect", "mutualTLS"]
    location: Literal["header", "query", "cookie"] | None = None
    parameter_name: str | None = Field(default=None, min_length=1, max_length=200)
    http_scheme: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        pattern=_HTTP_AUTH_SCHEME_PATTERN,
    )
    oauth_flows: tuple[
        Literal["authorizationCode", "clientCredentials", "implicit", "password"],
        ...,
    ] = Field(default=(), max_length=4)

    @field_validator("parameter_name")
    @classmethod
    def validate_parameter_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = _require_safe_text(value, label="Authentication parameter name")
        if any(character.isspace() for character in value):
            raise ValueError("Authentication parameter name cannot contain whitespace")
        return value

    @field_validator("http_scheme", mode="before")
    @classmethod
    def normalize_http_scheme(cls, value: object) -> object:
        return value.lower() if isinstance(value, str) else value

    @field_validator("oauth_flows", mode="before")
    @classmethod
    def normalize_oauth_flows(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            raise ValueError("OAuth flows must be a list or tuple")
        if any(not isinstance(item, str) for item in value):
            raise ValueError("OAuth flow must be text")
        normalized = tuple(sorted(value))
        if normalized != tuple(dict.fromkeys(normalized)):
            raise ValueError("OAuth flows must be unique and sorted")
        return normalized

    @model_validator(mode="after")
    def validate_scheme_shape(self) -> HTTPAuthenticationScheme:
        if self.scheme_type == "apiKey":
            if (
                self.location is None
                or self.parameter_name is None
                or self.http_scheme is not None
                or self.oauth_flows
            ):
                raise ValueError("apiKey authentication scheme fields are inconsistent")
            return self
        if self.scheme_type == "http":
            if (
                self.http_scheme is None
                or self.location is not None
                or self.parameter_name is not None
                or self.oauth_flows
            ):
                raise ValueError("HTTP authentication scheme fields are inconsistent")
            return self
        if self.scheme_type == "oauth2":
            if (
                not self.oauth_flows
                or self.location is not None
                or self.parameter_name is not None
                or self.http_scheme is not None
            ):
                raise ValueError("OAuth2 authentication scheme fields are inconsistent")
            return self
        if (
            self.location is not None
            or self.parameter_name is not None
            or self.http_scheme is not None
            or self.oauth_flows
        ):
            raise ValueError("Authentication scheme contains fields for another scheme type")
        return self


class HTTPAuthenticationRequirementEntry(StrictModel):
    """One scheme and its non-secret OAuth/OpenID scope names."""

    scheme_id: _PortableIdentifier
    scopes: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("scopes", mode="before")
    @classmethod
    def normalize_scopes(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            raise ValueError("Authentication scopes must be a list or tuple")
        scopes: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError("Authentication scope must be text")
            scope = _require_safe_text(item, label="Authentication scope")
            if not scope or len(scope) > 200 or any(character.isspace() for character in scope):
                raise ValueError("Authentication scope is invalid")
            scopes.append(scope)
        if scopes != sorted(set(scopes)):
            raise ValueError("Authentication scopes must be unique and sorted")
        return tuple(scopes)


class HTTPAuthenticationRequirement(StrictModel):
    """One AND requirement inside OpenAPI's OR security alternatives."""

    schemes: tuple[HTTPAuthenticationRequirementEntry, ...] = Field(
        min_length=1,
        max_length=16,
    )

    @field_validator("schemes")
    @classmethod
    def validate_schemes(
        cls,
        value: tuple[HTTPAuthenticationRequirementEntry, ...],
    ) -> tuple[HTTPAuthenticationRequirementEntry, ...]:
        scheme_ids = [item.scheme_id for item in value]
        if scheme_ids != sorted(set(scheme_ids)):
            raise ValueError("Authentication requirement schemes must be unique and sorted")
        return value


class HTTPAuthenticationSurfaceLocator(StrictModel):
    """Non-executable authentication boundary declared for one HTTP route."""

    kind: Literal["http-authentication"] = "http-authentication"
    route: HTTPRouteSurfaceLocator
    schemes: tuple[HTTPAuthenticationScheme, ...] = Field(min_length=1, max_length=32)
    requirements: tuple[HTTPAuthenticationRequirement, ...] = Field(
        min_length=1,
        max_length=16,
    )
    allows_anonymous: bool = False

    @model_validator(mode="after")
    def validate_authentication_contract(self) -> HTTPAuthenticationSurfaceLocator:
        scheme_ids = [item.scheme_id for item in self.schemes]
        if scheme_ids != sorted(set(scheme_ids)):
            raise ValueError("Authentication schemes must be unique and sorted")
        requirement_keys = [
            tuple((entry.scheme_id, entry.scopes) for entry in requirement.schemes)
            for requirement in self.requirements
        ]
        if requirement_keys != sorted(set(requirement_keys)):
            raise ValueError("Authentication requirements must be unique and sorted")
        referenced = {
            entry.scheme_id
            for requirement in self.requirements
            for entry in requirement.schemes
        }
        if referenced != set(scheme_ids):
            raise ValueError("Authentication schemes must exactly match referenced requirements")
        scheme_by_id = {item.scheme_id: item for item in self.schemes}
        for requirement in self.requirements:
            for entry in requirement.schemes:
                scheme = scheme_by_id[entry.scheme_id]
                if entry.scopes and scheme.scheme_type not in {"oauth2", "openIdConnect"}:
                    raise ValueError(
                        "Authentication scopes require an OAuth2 or OpenID Connect scheme"
                    )
        return self


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
    HTTPSurfaceLocator
    | HTTPRouteSurfaceLocator
    | HTTPAuthenticationSurfaceLocator
    | ToolInterfaceSurfaceLocator,
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


def http_route_surface_locator(
    *,
    base_url: str,
    path_template: str,
    method: str,
    request_content_types: tuple[str, ...] = (),
    response_content_types: tuple[str, ...] = (),
) -> HTTPRouteSurfaceLocator:
    """Build one canonical non-executable HTTP route template."""

    return HTTPRouteSurfaceLocator(
        base_url=base_url,
        path_template=path_template,
        method=method,
        request_content_types=request_content_types,
        response_content_types=response_content_types,
    )


def http_route_scope_url(locator: HTTPRouteSurfaceLocator) -> str:
    """Render a route template to one safe URL used only for Scope evaluation."""

    parsed = urlsplit(locator.base_url)
    rendered_path = sub(
        _ROUTE_PARAMETER_PATTERN,
        "pajin-route-parameter",
        http_route_path_template(locator),
    )
    return normalize_target_url(
        urlunsplit((parsed.scheme, parsed.netloc, rendered_path or "/", "", ""))
    )


def http_route_path_template(locator: HTTPRouteSurfaceLocator) -> str:
    """Return the effective absolute path template under its OpenAPI server base."""

    parsed = urlsplit(locator.base_url)
    base_path = parsed.path.rstrip("/")
    return f"{base_path}{locator.path_template}" if base_path else locator.path_template


def http_authentication_surface_locator(
    *,
    route: HTTPRouteSurfaceLocator,
    schemes: tuple[HTTPAuthenticationScheme, ...],
    requirements: tuple[HTTPAuthenticationRequirement, ...],
    allows_anonymous: bool = False,
) -> HTTPAuthenticationSurfaceLocator:
    """Build one canonical non-executable HTTP authentication boundary."""

    return HTTPAuthenticationSurfaceLocator(
        route=route.model_copy(deep=True),
        schemes=tuple(scheme.model_copy(deep=True) for scheme in schemes),
        requirements=tuple(
            requirement.model_copy(deep=True) for requirement in requirements
        ),
        allows_anonymous=allows_anonymous,
    )


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
