"""Versioned, code-owned discovery adapter authority."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Literal, Protocol, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.stable_context import stable_execution_context
from pajin.tools.base import ToolRegistry, ToolSpec

if TYPE_CHECKING:
    from pajin.discovery.admission import SurfaceCandidate

DISCOVERY_ADAPTER_API_VERSION: Literal["pajin.dev/discovery-adapter/v1alpha1"] = (
    "pajin.dev/discovery-adapter/v1alpha1"
)

DiscoverySurfaceKind = Literal[
    "http-authentication",
    "http-endpoint",
    "http-file-upload",
    "http-route",
    "tool-interface",
]

_MAX_ADAPTER_DEFINITION_BYTES = 256 * 1024
_MAX_ADAPTER_CONTEXT_BYTES = 64 * 1024
_MAX_ADAPTER_CONTEXT_DEPTH = 16
_MAX_ADAPTER_CONTEXT_NODES = 1_024

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_ImplementationType = Annotated[
    str,
    Field(min_length=3, max_length=500, pattern=r"^[A-Za-z_][A-Za-z0-9_.]{2,499}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]

_SENSITIVE_CONTEXT_KEY_PARTS = frozenset(
    {
        "accesskey",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "password",
        "privatekey",
        "secret",
        "token",
    }
)


class DiscoveryAdapterError(ValueError):
    """Raised when discovery adapter authority is invalid or has drifted."""


class DiscoveryAdapterReference(StrictModel):
    """Exact ID, version, and digest reference without a latest fallback."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    adapter_id: _Identifier = Field(alias="adapterId")
    adapter_version: _Identifier = Field(alias="adapterVersion")
    adapter_digest: _Sha256 = Field(alias="adapterDigest")


class DiscoveryAdapterToolBinding(StrictModel):
    """Exact Tool contract interpreted by one discovery adapter version."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    tool_id: _Identifier = Field(alias="toolId")
    tool_version: _Identifier = Field(alias="toolVersion")
    tool_digest: _Sha256 = Field(alias="toolDigest")


class DiscoveryAdapterDefinition(StrictModel):
    """Immutable authority metadata for one code-owned adapter version."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/discovery-adapter/v1alpha1"] = Field(
        default=DISCOVERY_ADAPTER_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DiscoveryAdapterDefinition"] = "DiscoveryAdapterDefinition"
    adapter_id: _Identifier = Field(alias="adapterId")
    adapter_version: _Identifier = Field(alias="adapterVersion")
    adapter_digest: str = Field(default="", alias="adapterDigest", max_length=64)
    producer_id: _Identifier = Field(alias="producerId")
    tool: DiscoveryAdapterToolBinding
    supported_surface_kinds: tuple[DiscoverySurfaceKind, ...] = Field(
        alias="supportedSurfaceKinds",
        min_length=1,
        max_length=20,
    )
    requires_trusted_network_receipt: bool = Field(
        default=False,
        alias="requiresTrustedNetworkReceipt",
    )
    implementation_type: _ImplementationType = Field(alias="implementationType")
    execution_context_digest: _Sha256 = Field(alias="executionContextDigest")

    @model_validator(mode="after")
    def bind_definition_digest(self) -> Self:
        if tuple(self.supported_surface_kinds) != tuple(sorted(set(self.supported_surface_kinds))):
            raise ValueError("Discovery adapter Surface kinds must be unique and sorted")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"adapter_digest"},
        )
        if not self.requires_trusted_network_receipt:
            material.pop("requiresTrustedNetworkReceipt")
        digest = discovery_digest("pajin.discovery.adapter-definition/v1", material)
        if self.adapter_digest and self.adapter_digest != digest:
            raise ValueError("Discovery adapter digest differs from canonical identity")
        object.__setattr__(self, "adapter_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="DiscoveryAdapterDefinition",
            max_bytes=_MAX_ADAPTER_DEFINITION_BYTES,
        )
        return self

    def reference(self) -> DiscoveryAdapterReference:
        """Return a detached exact-version reference."""

        return DiscoveryAdapterReference(
            adapterId=self.adapter_id,
            adapterVersion=self.adapter_version,
            adapterDigest=self.adapter_digest,
        )


class DiscoveryAdapter(Protocol):
    """Code-owned interpreter for one registered discovery Tool result."""

    adapter_id: str
    adapter_version: str
    producer_id: str
    tool_id: str
    supported_surface_kinds: tuple[DiscoverySurfaceKind, ...]
    requires_trusted_network_receipt: bool

    def stable_execution_context(self) -> Mapping[str, object]:
        """Expose every non-secret setting that changes result interpretation."""

    def extract_surfaces(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Sequence[SurfaceCandidate]:
        """Return bounded non-authoritative candidates from one Tool result."""


@dataclass(frozen=True, slots=True)
class RegisteredDiscoveryAdapter:
    """One runtime adapter paired with its immutable authority definition."""

    definition: DiscoveryAdapterDefinition
    adapter: DiscoveryAdapter


class DiscoveryAdapterRegistry:
    """Explicit adapter registry with exact resolution and drift detection."""

    def __init__(
        self,
        *,
        tools: ToolRegistry,
        adapters: Iterable[DiscoveryAdapter],
    ) -> None:
        if not isinstance(tools, ToolRegistry):
            raise TypeError("Discovery adapter registry requires a ToolRegistry")
        self._tools = tools
        records: dict[tuple[str, str], RegisteredDiscoveryAdapter] = {}
        for adapter in adapters:
            definition = self._snapshot_definition(adapter)
            key = (definition.adapter_id, definition.adapter_version)
            if key in records:
                raise DiscoveryAdapterError(
                    "Discovery adapter registry contains a duplicate ID and version"
                )
            records[key] = RegisteredDiscoveryAdapter(
                definition=definition,
                adapter=adapter,
            )
        if not records:
            raise DiscoveryAdapterError("Discovery adapter registry requires at least one adapter")
        self._records = records

    def require_tool_registry(self, tools: ToolRegistry) -> None:
        """Reject composition with a different Tool authority root."""

        if tools is not self._tools:
            raise DiscoveryAdapterError(
                "Discovery adapter and Surface producer require the same ToolRegistry"
            )

    def resolve(
        self,
        reference: DiscoveryAdapterReference,
    ) -> RegisteredDiscoveryAdapter:
        """Resolve one exact reference and revalidate live adapter state."""

        canonical_reference = _canonical_reference(reference)
        key = (canonical_reference.adapter_id, canonical_reference.adapter_version)
        try:
            registered = self._records[key]
        except KeyError as exc:
            raise DiscoveryAdapterError("Discovery adapter is not registered") from exc
        if registered.definition.reference() != canonical_reference:
            raise DiscoveryAdapterError(
                "Discovery adapter version or digest differs from the registry"
            )
        try:
            current = self._snapshot_definition(registered.adapter)
        except (DiscoveryAdapterError, RuntimeError, TypeError, ValueError) as exc:
            raise DiscoveryAdapterError(
                "Discovery adapter authority is unavailable or has drifted"
            ) from exc
        if current != registered.definition:
            raise DiscoveryAdapterError("Discovery adapter changed after registration")
        return RegisteredDiscoveryAdapter(
            definition=_canonical_definition(registered.definition),
            adapter=registered.adapter,
        )

    def select(
        self,
        references: Iterable[DiscoveryAdapterReference],
    ) -> tuple[RegisteredDiscoveryAdapter, ...]:
        """Resolve an explicit set and reject duplicate references or Tool interpreters."""

        selected: list[RegisteredDiscoveryAdapter] = []
        seen_references: set[tuple[str, str, str]] = set()
        seen_tools: set[str] = set()
        for reference in references:
            canonical = _canonical_reference(reference)
            reference_key = (
                canonical.adapter_id,
                canonical.adapter_version,
                canonical.adapter_digest,
            )
            if reference_key in seen_references:
                raise DiscoveryAdapterError("Discovery adapter selection contains a duplicate")
            registered = self.resolve(canonical)
            tool_id = registered.definition.tool.tool_id
            if tool_id in seen_tools:
                raise DiscoveryAdapterError(
                    "Discovery adapter selection contains multiple interpreters for one Tool"
                )
            seen_references.add(reference_key)
            seen_tools.add(tool_id)
            selected.append(registered)
        if not selected:
            raise DiscoveryAdapterError("Discovery adapter selection cannot be empty")
        return tuple(
            sorted(
                selected,
                key=lambda item: (
                    item.definition.adapter_id,
                    item.definition.adapter_version,
                ),
            )
        )

    def definitions(self) -> tuple[DiscoveryAdapterDefinition, ...]:
        """Return detached definitions in canonical ID/version order."""

        return tuple(
            _canonical_definition(self._records[key].definition) for key in sorted(self._records)
        )

    def _snapshot_definition(
        self,
        adapter: DiscoveryAdapter,
    ) -> DiscoveryAdapterDefinition:
        extractor = getattr(adapter, "extract_surfaces", None)
        if not callable(extractor):
            raise DiscoveryAdapterError("Discovery adapter extractor is invalid")
        try:
            tool_id = adapter.tool_id
            self._tools.tool(tool_id)
            tool_spec = self._tools.spec(tool_id)
            stable_context = _canonical_stable_context(adapter)
            implementation_type = stable_context.get("type")
            if not isinstance(implementation_type, str):
                raise DiscoveryAdapterError("Discovery adapter implementation identity is invalid")
            definition = DiscoveryAdapterDefinition(
                adapterId=adapter.adapter_id,
                adapterVersion=adapter.adapter_version,
                producerId=adapter.producer_id,
                tool=DiscoveryAdapterToolBinding(
                    toolId=tool_spec.tool_id,
                    toolVersion=tool_spec.version,
                    toolDigest=_tool_spec_digest(tool_spec),
                ),
                supportedSurfaceKinds=adapter.supported_surface_kinds,
                requiresTrustedNetworkReceipt=adapter.requires_trusted_network_receipt,
                implementationType=implementation_type,
                executionContextDigest=discovery_digest(
                    "pajin.discovery.adapter-execution-context/v1",
                    stable_context,
                ),
            )
        except DiscoveryAdapterError:
            raise
        except (
            AttributeError,
            KeyError,
            RuntimeError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise DiscoveryAdapterError(
                "Discovery adapter contract is invalid or its Tool is unavailable"
            ) from exc
        return definition


def _canonical_reference(
    reference: DiscoveryAdapterReference,
) -> DiscoveryAdapterReference:
    try:
        return DiscoveryAdapterReference.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise DiscoveryAdapterError("Discovery adapter reference is not canonical") from exc


def _canonical_definition(
    definition: DiscoveryAdapterDefinition,
) -> DiscoveryAdapterDefinition:
    try:
        return DiscoveryAdapterDefinition.model_validate(
            definition.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise DiscoveryAdapterError("Discovery adapter definition is not canonical") from exc


def _canonical_stable_context(adapter: object) -> dict[str, object]:
    try:
        value = stable_execution_context(adapter, component="Discovery adapter")
        encoded = canonical_json_bytes(
            value,
            label="Discovery adapter stable execution context",
            max_bytes=_MAX_ADAPTER_CONTEXT_BYTES,
        )
        canonical = parse_strict_json_bytes(
            encoded,
            label="Discovery adapter stable execution context",
            max_bytes=_MAX_ADAPTER_CONTEXT_BYTES,
            max_depth=_MAX_ADAPTER_CONTEXT_DEPTH,
            max_nodes=_MAX_ADAPTER_CONTEXT_NODES,
        )
    except (TypeError, ValueError) as exc:
        raise DiscoveryAdapterError(
            "Discovery adapter stable execution context is invalid"
        ) from exc
    if not isinstance(canonical, dict):
        raise DiscoveryAdapterError("Discovery adapter stable execution context must be an object")
    _reject_sensitive_context_keys(canonical)
    return canonical


def _reject_sensitive_context_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = "".join(character for character in key.lower() if character.isalnum())
            if any(part in normalized for part in _SENSITIVE_CONTEXT_KEY_PARTS):
                raise DiscoveryAdapterError(
                    "Discovery adapter stable execution context contains a secret-like key"
                )
            _reject_sensitive_context_keys(item)
    elif isinstance(value, list):
        for item in value:
            _reject_sensitive_context_keys(item)


def _tool_spec_digest(spec: ToolSpec) -> str:
    snapshot = ToolSpec.model_validate(spec.model_dump(mode="python"))
    return discovery_digest(
        "pajin.discovery.tool-spec/v1",
        {
            "toolId": snapshot.tool_id,
            "version": snapshot.version,
            "description": snapshot.description,
            "riskTier": int(snapshot.risk_tier),
            "categories": sorted(snapshot.categories),
            "evidenceTypes": sorted(snapshot.evidence_types),
            "networkAccess": snapshot.network_access,
            "networkRequestCost": snapshot.network_request_cost,
            "parallelSafe": snapshot.parallel_safe,
        },
    )
