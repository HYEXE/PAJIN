"""Bounded references to existing sealed Run artifacts."""

from __future__ import annotations

from pathlib import Path
from re import fullmatch
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import CampaignManifest, StrictModel
from pajin.graph.models import (
    GraphEvidence,
    GraphEvidenceBinding,
    GraphNodeKind,
    GraphNodeRef,
    canonical_graph_json,
    graph_digest,
    graph_node_ref,
    parse_graph_node,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    RunIntegrityError,
    SealedArtifact,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
)

SHARED_ARTIFACT_REF_API_VERSION = "pajin.dev/shared-artifact-ref/v1alpha1"
MAX_SHARED_ARTIFACT_BYTES = 1024 * 1024
_MAX_CAMPAIGN_BYTES = 1024 * 1024
_MAX_SHARED_ARTIFACT_REF_BYTES = 16 * 1024
_SHARED_ARTIFACT_ID_PATTERN = r"^shared-artifact_[a-f0-9]{64}$"
_MEDIA_TYPE_PATTERN = r"^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$"


class SharedArtifactRefError(ValueError):
    """Raised when a shared Artifact reference is not an exact sealed projection."""


class SharedArtifactRef(StrictModel):
    """Non-authoritative metadata reference to one exact Graph Evidence artifact."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/shared-artifact-ref/v1alpha1"] = Field(
        default="pajin.dev/shared-artifact-ref/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["SharedArtifactRef"] = "SharedArtifactRef"
    shared_artifact_id: str = Field(default="", alias="sharedArtifactId", max_length=80)
    shared_artifact_digest: str = Field(
        default="",
        alias="sharedArtifactDigest",
        max_length=64,
    )
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    evidence: GraphNodeRef
    source_run_id: str = Field(
        alias="sourceRunId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    source_root_digest: str = Field(
        alias="sourceRootDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    relative_path: str = Field(alias="relativePath", min_length=1, max_length=2_000)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    media_type: str = Field(alias="mediaType", min_length=3, max_length=100)
    size_bytes: int = Field(
        alias="sizeBytes",
        strict=True,
        ge=0,
        le=MAX_SHARED_ARTIFACT_BYTES,
    )
    content_embedded: Literal[False] = Field(default=False, alias="contentEmbedded")
    prompt_relay_authorized: Literal[False] = Field(
        default=False,
        alias="promptRelayAuthorized",
    )
    receiver_authority_granted: Literal[False] = Field(
        default=False,
        alias="receiverAuthorityGranted",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("relative_path")
    @classmethod
    def require_graph_evidence_path(cls, value: str) -> str:
        return GraphEvidenceBinding(reference=value, sha256="0" * 64).reference

    @field_validator("media_type")
    @classmethod
    def require_canonical_media_type(cls, value: str) -> str:
        if fullmatch(_MEDIA_TYPE_PATTERN, value) is None:
            raise ValueError("shared Artifact media type must be canonical lowercase MIME")
        return value

    @field_validator(
        "content_embedded",
        "prompt_relay_authorized",
        "receiver_authority_granted",
        "scope_expansion_authorized",
        "capability_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_boolean_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("shared Artifact authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def require_canonical_identity_and_non_authority(self) -> Self:
        if (
            self.evidence.kind is not GraphNodeKind.EVIDENCE
            or self.evidence.campaign_id != self.campaign_id
        ):
            raise ValueError("shared Artifact Evidence belongs to another Campaign or kind")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"shared_artifact_id", "shared_artifact_digest"},
        )
        digest = graph_digest(
            "pajin.collaboration.shared-artifact-ref/v1",
            material,
            max_bytes=_MAX_SHARED_ARTIFACT_REF_BYTES,
        )
        shared_artifact_id = f"shared-artifact_{digest}"
        if self.shared_artifact_digest and self.shared_artifact_digest != digest:
            raise ValueError("shared Artifact digest differs from canonical identity")
        if self.shared_artifact_id and self.shared_artifact_id != shared_artifact_id:
            raise ValueError("shared Artifact ID differs from canonical identity")
        object.__setattr__(self, "shared_artifact_digest", digest)
        object.__setattr__(self, "shared_artifact_id", shared_artifact_id)
        if fullmatch(_SHARED_ARTIFACT_ID_PATTERN, self.shared_artifact_id) is None:
            raise ValueError("shared Artifact ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="SharedArtifactRef",
            max_bytes=_MAX_SHARED_ARTIFACT_REF_BYTES,
        )
        return self


def create_shared_artifact_ref(
    evidence: GraphEvidence,
    *,
    source_run_path: Path,
) -> SharedArtifactRef:
    """Create a metadata-only reference after verifying its exact sealed source."""

    canonical_evidence = _canonical_evidence(evidence)
    snapshot, record = _verified_source(
        canonical_evidence,
        source_run_path=source_run_path,
        expected_run_id=None,
    )
    return SharedArtifactRef(
        campaignId=canonical_evidence.campaign_id,
        evidence=graph_node_ref(canonical_evidence),
        sourceRunId=snapshot.verification.run_id,
        sourceRootDigest=snapshot.verification.root_digest,
        relativePath=record.path,
        sha256=record.sha256,
        mediaType=record.media_type,
        sizeBytes=record.size_bytes,
    )


def verify_shared_artifact_ref(
    reference: SharedArtifactRef,
    evidence: GraphEvidence,
    *,
    source_run_path: Path,
) -> SharedArtifactRef:
    """Reverify one reference without returning Artifact bytes or a filesystem path."""

    try:
        canonical_reference = SharedArtifactRef.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
        canonical_evidence = _canonical_evidence(evidence)
        snapshot, record = _verified_source(
            canonical_evidence,
            source_run_path=source_run_path,
            expected_run_id=canonical_reference.source_run_id,
        )
        if graph_node_ref(canonical_evidence) != canonical_reference.evidence:
            raise ValueError("shared Artifact Graph Evidence identity differs")
        if (
            canonical_reference.campaign_id != canonical_evidence.campaign_id
            or canonical_reference.source_root_digest != snapshot.verification.root_digest
            or canonical_reference.relative_path != record.path
            or canonical_reference.sha256 != record.sha256
            or canonical_reference.media_type != record.media_type
            or canonical_reference.size_bytes != record.size_bytes
        ):
            raise ValueError("shared Artifact reference differs from sealed source")
        return canonical_reference
    except SharedArtifactRefError:
        raise
    except (
        AttributeError,
        KeyError,
        OSError,
        RunIntegrityError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SharedArtifactRefError(
            "shared Artifact reference could not be verified"
        ) from exc


def _canonical_evidence(evidence: GraphEvidence) -> GraphEvidence:
    try:
        canonical = parse_graph_node(evidence.model_dump(mode="json", by_alias=True))
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise SharedArtifactRefError("shared Artifact Graph Evidence is invalid") from exc
    if not isinstance(canonical, GraphEvidence):
        raise SharedArtifactRefError("shared Artifact reference requires Graph Evidence")
    return canonical


def _verified_source(
    evidence: GraphEvidence,
    *,
    source_run_path: Path,
    expected_run_id: str | None,
) -> tuple[VerifiedRunSnapshot, SealedArtifact]:
    try:
        if evidence.reference == "campaign.json":
            raise ValueError("Campaign authority Artifact cannot be shared")
        snapshot = load_verified_run_artifacts(
            source_run_path,
            requests={
                "campaign.json": _MAX_CAMPAIGN_BYTES,
                evidence.reference: MAX_SHARED_ARTIFACT_BYTES,
            },
            expected_run_id=expected_run_id,
        )
        _require_campaign(snapshot, evidence.campaign_id)
        if snapshot.verification.root_digest != evidence.source_root_digest:
            raise ValueError("shared Artifact source root is stale or substituted")
        matches = [
            artifact
            for seal in snapshot.seals
            for artifact in seal.artifacts
            if artifact.path == evidence.reference
        ]
        if len(matches) != 1:
            raise ValueError("shared Artifact is not sealed exactly once")
        record = matches[0]
        if (
            record.sha256 != evidence.sha256
            or record.media_type != evidence.media_type
            or record.size_bytes > MAX_SHARED_ARTIFACT_BYTES
        ):
            raise ValueError("Graph Evidence differs from sealed Artifact metadata")
        return snapshot, record
    except SharedArtifactRefError:
        raise
    except (
        AttributeError,
        KeyError,
        OSError,
        RunIntegrityError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SharedArtifactRefError("shared Artifact source could not be verified") from exc


def _require_campaign(snapshot: VerifiedRunSnapshot, campaign_id: str) -> None:
    raw = parse_strict_json_bytes(
        snapshot.artifact_bytes("campaign.json"),
        label="shared Artifact Campaign",
        max_bytes=_MAX_CAMPAIGN_BYTES,
    )
    campaign = CampaignManifest.model_validate(raw)
    started = [event for event in snapshot.events if event.event_type == "campaign.started"]
    if (
        campaign.metadata.name != campaign_id
        or len(started) != 1
        or started[0].payload.get("campaign") != campaign_id
    ):
        raise ValueError("shared Artifact source Campaign differs")
