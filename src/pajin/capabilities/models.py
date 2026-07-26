"""Canonical versioned Capability definitions for PAJIN execution adapters."""

from __future__ import annotations

import json
from collections.abc import Iterable
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import StrictModel, ToolRiskTier

CAPABILITY_DEFINITION_API_VERSION: Literal["pajin.dev/capability-definition/v1alpha1"] = (
    "pajin.dev/capability-definition/v1alpha1"
)

_MAX_CAPABILITY_DEFINITION_BYTES = 256 * 1024
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class CapabilityDefinitionError(ValueError):
    """Raised when versioned Capability metadata is invalid or has drifted."""


class CapabilityMaturity(StrEnum):
    """Review state used to gate where a Capability may be activated."""

    EXPERIMENTAL = "experimental"
    CANARY = "canary"
    STABLE = "stable"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class CapabilitySideEffectClass(StrEnum):
    """Coarse side-effect ceiling declared by a Capability definition."""

    NONE = "none"
    READ_ONLY = "read-only"
    REVERSIBLE_WRITE = "reversible-write"
    IRREVERSIBLE_WRITE = "irreversible-write"


def canonical_capability_json(value: object, *, label: str) -> bytes:
    """Encode bounded canonical UTF-8 JSON for Capability identities."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise CapabilityDefinitionError(f"{label} is not canonical UTF-8 JSON") from exc
    if len(encoded) > _MAX_CAPABILITY_DEFINITION_BYTES:
        raise CapabilityDefinitionError(f"{label} exceeds the canonical byte limit")
    return encoded


def capability_definition_digest(domain: str, value: object) -> str:
    """Return a domain-separated digest for a Capability authority object."""

    try:
        domain_bytes = domain.encode("ascii")
    except UnicodeEncodeError as exc:
        raise CapabilityDefinitionError("Capability digest domain must be ASCII") from exc
    encoded = canonical_capability_json(value, label=domain)
    return sha256(
        b"PAJIN-CAPABILITY\0"
        + len(domain_bytes).to_bytes(4, "big")
        + domain_bytes
        + len(encoded).to_bytes(8, "big")
        + encoded
    ).hexdigest()


class CapabilityDefinitionRef(StrictModel):
    """Exact ID, version, and digest reference to one Capability definition."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    capability_id: _Identifier = Field(alias="capabilityId")
    capability_version: _Identifier = Field(alias="capabilityVersion")
    capability_digest: _Sha256 = Field(alias="capabilityDigest")


class CapabilityToolBinding(StrictModel):
    """Exact registered Tool contract used by one Capability version."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    tool_id: _Identifier = Field(alias="toolId")
    tool_version: _Identifier = Field(alias="toolVersion")
    tool_digest: _Sha256 = Field(alias="toolDigest")


class CapabilityDefinition(StrictModel):
    """Immutable declarative metadata for one executable Capability version."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-definition/v1alpha1"] = Field(
        default=CAPABILITY_DEFINITION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityDefinition"] = "CapabilityDefinition"
    capability_id: _Identifier = Field(alias="capabilityId")
    capability_version: _Identifier = Field(alias="capabilityVersion")
    capability_digest: str = Field(default="", alias="capabilityDigest", max_length=64)
    domain: _Identifier
    maturity: CapabilityMaturity
    supported_surface_types: tuple[_Identifier, ...] = Field(
        alias="supportedSurfaceTypes",
        min_length=1,
        max_length=100,
    )
    threat_classes: tuple[_Identifier, ...] = Field(
        alias="threatClasses",
        min_length=1,
        max_length=100,
    )
    preconditions: tuple[_Identifier, ...] = Field(default=(), max_length=100)
    parameter_schema_digest: _Sha256 = Field(alias="parameterSchemaDigest")
    tool: CapabilityToolBinding
    risk_tier: ToolRiskTier = Field(alias="riskTier")
    side_effect_class: CapabilitySideEffectClass = Field(alias="sideEffectClass")
    evidence_types: tuple[_Identifier, ...] = Field(
        alias="evidenceTypes",
        min_length=1,
        max_length=100,
    )
    network_access: bool = Field(alias="networkAccess")
    approval_required: bool = Field(alias="approvalRequired")
    request_unit_cost: int = Field(alias="requestUnitCost", ge=1, le=100)
    cleanup_required: bool = Field(alias="cleanupRequired")
    parallel_safe: bool = Field(alias="parallelSafe")

    @field_validator("risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)

    @model_validator(mode="after")
    def bind_definition_digest(self) -> Self:
        for field_name, label in (
            ("supported_surface_types", "supported Surface types"),
            ("threat_classes", "threat classes"),
            ("preconditions", "preconditions"),
            ("evidence_types", "evidence types"),
        ):
            values = getattr(self, field_name)
            if tuple(values) != tuple(sorted(set(values))):
                raise ValueError(f"Capability {label} must be unique and sorted")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"capability_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.definition/v1",
            material,
        )
        if self.capability_digest and self.capability_digest != digest:
            raise ValueError("Capability definition digest differs from canonical identity")
        object.__setattr__(self, "capability_digest", digest)
        canonical_capability_json(
            self.model_dump(mode="json", by_alias=True),
            label="CapabilityDefinition",
        )
        return self

    def reference(self) -> CapabilityDefinitionRef:
        """Return a detached exact-version reference."""

        return CapabilityDefinitionRef(
            capabilityId=self.capability_id,
            capabilityVersion=self.capability_version,
            capabilityDigest=self.capability_digest,
        )


class CapabilityDefinitionRegistry:
    """Immutable registry that never performs implicit latest-version resolution."""

    def __init__(self, definitions: Iterable[CapabilityDefinition]) -> None:
        records: dict[tuple[str, str], CapabilityDefinition] = {}
        for definition in definitions:
            canonical = self._canonical_definition(definition)
            key = (canonical.capability_id, canonical.capability_version)
            if key in records:
                raise CapabilityDefinitionError(
                    "Capability registry contains a duplicate ID and version"
                )
            records[key] = canonical
        self._records = records

    def resolve(self, reference: CapabilityDefinitionRef) -> CapabilityDefinition:
        """Resolve only an exact ID, version, and digest tuple."""

        try:
            definition = self._records[
                (reference.capability_id, reference.capability_version)
            ]
        except KeyError as exc:
            raise CapabilityDefinitionError("Capability definition is not registered") from exc
        if definition.reference() != reference:
            raise CapabilityDefinitionError(
                "Capability definition version or digest differs from the registry"
            )
        return definition.model_copy(deep=True)

    def definitions(self) -> tuple[CapabilityDefinition, ...]:
        """Return detached definitions in canonical ID/version order."""

        return tuple(
            self._records[key].model_copy(deep=True) for key in sorted(self._records)
        )

    @staticmethod
    def _canonical_definition(definition: CapabilityDefinition) -> CapabilityDefinition:
        try:
            return CapabilityDefinition.model_validate(
                definition.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise CapabilityDefinitionError(
                "Capability registry input is not canonical"
            ) from exc
