"""P0-D3B1 non-runnable topology and transfer contract for a Hybrid provider."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.hybrid_target_composition import (
    HybridTargetGroundTruthBinding,
    HybridTargetSelectionAuthority,
    select_hybrid_target_composition,
)
from pajin.benchmark.models import benchmark_digest
from pajin.benchmark.target_catalog import BenchmarkTargetCatalogError
from pajin.domain.models import StrictModel

HYBRID_TRANSFER_ARTIFACT_SCHEMA_API_VERSION: Literal[
    "pajin.dev/hybrid-transfer-artifact-schema/v1alpha1"
] = "pajin.dev/hybrid-transfer-artifact-schema/v1alpha1"
HYBRID_PROVIDER_TOPOLOGY_API_VERSION: Literal[
    "pajin.dev/hybrid-provider-topology/v1alpha1"
] = "pajin.dev/hybrid-provider-topology/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_TRANSFER_SCHEMA_BYTES = 128 * 1024
_MAX_TOPOLOGY_BYTES = 4 * 1024 * 1024

_SERVICE_ORDER = (
    "hybrid-traditional-target",
    "hybrid-ai-rag-mcp-target",
    "hybrid-benchmark-worker",
)
_CLEANUP_ORDER = tuple(reversed(_SERVICE_ORDER))
_BRIDGE_ORDER = (
    "execute-traditional-probe",
    "seal-traditional-response",
    "extract-transfer-document",
    "seal-transfer-artifact",
    "upload-transfer-document",
    "execute-ai-rag-mcp-probe",
)
_TRANSFER_FIELDS = (
    "schemaVersion",
    "sourceObservationDigest",
    "sourceResponseDigest",
    "documentId",
    "documentContent",
)


class HybridProviderContractError(RuntimeError):
    """Raised when a Hybrid provider topology cannot be bound exactly."""


class HybridTransferArtifactSchemaAuthority(StrictModel):
    """Exact schema required to prove the component-to-component data transfer."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/hybrid-transfer-artifact-schema/v1alpha1"
    ] = Field(
        default=HYBRID_TRANSFER_ARTIFACT_SCHEMA_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["HybridTransferArtifactSchemaAuthority"] = (
        "HybridTransferArtifactSchemaAuthority"
    )
    schema_id: str = Field(default="", alias="schemaId", max_length=120)
    schema_digest: str = Field(default="", alias="schemaDigest", max_length=64)
    bridge_digest: _Sha256 = Field(alias="bridgeDigest")
    source_component_digest: _Sha256 = Field(alias="sourceComponentDigest")
    destination_component_digest: _Sha256 = Field(
        alias="destinationComponentDigest"
    )
    media_type: Literal["application/vnd.pajin.hybrid-transfer+json"] = Field(
        default="application/vnd.pajin.hybrid-transfer+json",
        alias="mediaType",
    )
    schema_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="schemaVersion",
    )
    source_document_pointer: Literal["/records/0/documentContent"] = Field(
        default="/records/0/documentContent",
        alias="sourceDocumentPointer",
    )
    destination_upload_path: Literal["/documents"] = Field(
        default="/documents",
        alias="destinationUploadPath",
    )
    destination_document_id: Literal["document:hybrid-sqli-transfer"] = Field(
        default="document:hybrid-sqli-transfer",
        alias="destinationDocumentId",
    )
    artifact_fields: tuple[str, ...] = Field(
        default=_TRANSFER_FIELDS,
        alias="artifactFields",
        min_length=len(_TRANSFER_FIELDS),
        max_length=len(_TRANSFER_FIELDS),
    )
    source_field_required: Literal[True] = Field(
        default=True,
        alias="sourceFieldRequired",
    )
    canonical_json_required: Literal[True] = Field(
        default=True,
        alias="canonicalJsonRequired",
    )
    source_response_digest_required: Literal[True] = Field(
        default=True,
        alias="sourceResponseDigestRequired",
    )
    transfer_state: Literal["schema-registered-not-executed"] = Field(
        default="schema-registered-not-executed",
        alias="transferState",
    )
    execution_receipt_required: Literal[True] = Field(
        default=True,
        alias="executionReceiptRequired",
    )

    @field_validator("artifact_fields")
    @classmethod
    def require_exact_artifact_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != _TRANSFER_FIELDS:
            raise ValueError("Hybrid transfer artifact field order differs")
        return value

    @model_validator(mode="after")
    def bind_schema(self) -> Self:
        if self.source_component_digest == self.destination_component_digest:
            raise ValueError("Hybrid transfer components must be distinct")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"schema_id", "schema_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.hybrid-transfer-artifact-schema/v1",
            material,
            max_bytes=_MAX_TRANSFER_SCHEMA_BYTES,
        )
        schema_id = f"hybrid-transfer-artifact-schema:{digest}"
        if self.schema_digest and self.schema_digest != digest:
            raise ValueError("Hybrid Transfer Artifact Schema Digest differs")
        if self.schema_id and self.schema_id != schema_id:
            raise ValueError("Hybrid Transfer Artifact Schema ID differs")
        object.__setattr__(self, "schema_digest", digest)
        object.__setattr__(self, "schema_id", schema_id)
        return self


class HybridProviderTopologyAuthority(StrictModel):
    """Planned multi-container boundary that grants no provider execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/hybrid-provider-topology/v1alpha1"] = Field(
        default=HYBRID_PROVIDER_TOPOLOGY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["HybridProviderTopologyAuthority"] = (
        "HybridProviderTopologyAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=120)
    authority_digest: str = Field(
        default="",
        alias="authorityDigest",
        max_length=64,
    )
    predecessor_selection: HybridTargetSelectionAuthority = Field(
        alias="predecessorSelection"
    )
    ground_truth_binding_digest: _Sha256 = Field(alias="groundTruthBindingDigest")
    transfer_schema: HybridTransferArtifactSchemaAuthority = Field(
        alias="transferSchema"
    )
    target_factory_id: Literal["target-factory:docker-hybrid-sqli-rag-mcp"] = Field(
        default="target-factory:docker-hybrid-sqli-rag-mcp",
        alias="targetFactoryId",
    )
    target_factory_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="targetFactoryVersion",
    )
    adapter_id: Literal["target-adapter:docker-hybrid-sqli-rag-mcp"] = Field(
        default="target-adapter:docker-hybrid-sqli-rag-mcp",
        alias="adapterId",
    )
    adapter_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="adapterVersion",
    )
    network_mode: Literal["shared-internal-bridge-no-published-ports"] = Field(
        default="shared-internal-bridge-no-published-ports",
        alias="networkMode",
    )
    service_startup_order: tuple[str, ...] = Field(
        default=_SERVICE_ORDER,
        alias="serviceStartupOrder",
        min_length=len(_SERVICE_ORDER),
        max_length=len(_SERVICE_ORDER),
    )
    cleanup_order: tuple[str, ...] = Field(
        default=_CLEANUP_ORDER,
        alias="cleanupOrder",
        min_length=len(_CLEANUP_ORDER),
        max_length=len(_CLEANUP_ORDER),
    )
    bridge_execution_order: tuple[str, ...] = Field(
        default=_BRIDGE_ORDER,
        alias="bridgeExecutionOrder",
        min_length=len(_BRIDGE_ORDER),
        max_length=len(_BRIDGE_ORDER),
    )
    operation_journal_mode: Literal[
        "single-coordinate-single-fence-ordered-components"
    ] = Field(
        default="single-coordinate-single-fence-ordered-components",
        alias="operationJournalMode",
    )
    image_binding_state: Literal["required-not-bound"] = Field(
        default="required-not-bound",
        alias="imageBindingState",
    )
    adapter_registration_state: Literal["planned-not-registered"] = Field(
        default="planned-not-registered",
        alias="adapterRegistrationState",
    )
    execution_availability: Literal["provider-contract-only"] = Field(
        default="provider-contract-only",
        alias="executionAvailability",
    )
    provider_execution_authorized: Literal[False] = Field(
        default=False,
        alias="providerExecutionAuthorized",
    )
    benchmark_manifest_eligible: Literal[False] = Field(
        default=False,
        alias="benchmarkManifestEligible",
    )
    measurement_admission_eligible: Literal[False] = Field(
        default=False,
        alias="measurementAdmissionEligible",
    )
    bridge_execution_observed: Literal[False] = Field(
        default=False,
        alias="bridgeExecutionObserved",
    )

    @field_validator("service_startup_order")
    @classmethod
    def require_exact_startup_order(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != _SERVICE_ORDER:
            raise ValueError("Hybrid provider service startup order differs")
        return value

    @field_validator("cleanup_order")
    @classmethod
    def require_exact_cleanup_order(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != _CLEANUP_ORDER:
            raise ValueError("Hybrid provider cleanup order differs")
        return value

    @field_validator("bridge_execution_order")
    @classmethod
    def require_exact_bridge_order(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != _BRIDGE_ORDER:
            raise ValueError("Hybrid provider bridge execution order differs")
        return value

    @model_validator(mode="after")
    def bind_topology(self) -> Self:
        composition = self.predecessor_selection.composition
        components = composition.components
        if (
            self.ground_truth_binding_digest
            != self.predecessor_selection.ground_truth_binding_digest
            or self.transfer_schema.bridge_digest != composition.bridge.bridge_digest
            or self.transfer_schema.source_component_digest
            != components[0].component_digest
            or self.transfer_schema.destination_component_digest
            != components[1].component_digest
        ):
            raise ValueError("Hybrid provider predecessor or transfer binding differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.hybrid-provider-topology/v1",
            material,
            max_bytes=_MAX_TOPOLOGY_BYTES,
        )
        authority_id = f"hybrid-provider-topology:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Hybrid Provider Topology Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Hybrid Provider Topology Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


def registered_hybrid_provider_topology(
    selection: HybridTargetSelectionAuthority,
    ground_truth: HybridTargetGroundTruthBinding,
) -> HybridProviderTopologyAuthority:
    """Bind a P0-D3 selection to the exact prerequisites of a future provider."""

    try:
        authoritative_selection = HybridTargetSelectionAuthority.model_validate(
            selection.model_dump(mode="json", by_alias=True)
        )
        authoritative_ground_truth = HybridTargetGroundTruthBinding.model_validate(
            ground_truth.model_dump(mode="json", by_alias=True)
        )
        expected_selection = select_hybrid_target_composition(
            authoritative_selection.composition,
            authoritative_ground_truth,
        )
        if expected_selection != authoritative_selection:
            raise ValueError("Hybrid provider selection differs from private binding")
        components = authoritative_selection.composition.components
        transfer = HybridTransferArtifactSchemaAuthority(
            bridgeDigest=authoritative_selection.composition.bridge.bridge_digest,
            sourceComponentDigest=components[0].component_digest,
            destinationComponentDigest=components[1].component_digest,
        )
        return HybridProviderTopologyAuthority(
            predecessorSelection=authoritative_selection,
            groundTruthBindingDigest=authoritative_ground_truth.binding_digest,
            transferSchema=transfer,
        )
    except (BenchmarkTargetCatalogError, TypeError, ValueError) as exc:
        raise HybridProviderContractError(
            "Hybrid provider topology registration failed"
        ) from exc
