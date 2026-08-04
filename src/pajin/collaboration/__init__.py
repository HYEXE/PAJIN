"""Structured collaboration projections derived from existing PAJIN authorities."""

from pajin.collaboration.artifacts import (
    MAX_SHARED_ARTIFACT_BYTES,
    SHARED_ARTIFACT_REF_API_VERSION,
    SharedArtifactRef,
    SharedArtifactRefError,
    create_shared_artifact_ref,
    verify_shared_artifact_ref,
)
from pajin.collaboration.snapshots import (
    COLLABORATION_SNAPSHOT_API_VERSION,
    MAX_COLLABORATION_ARTIFACTS,
    MAX_COLLABORATION_FACTS,
    CollaborationSnapshot,
    CollaborationSnapshotError,
    SharedArtifactSource,
    create_collaboration_snapshot,
    verify_collaboration_snapshot,
)

__all__ = [
    "COLLABORATION_SNAPSHOT_API_VERSION",
    "MAX_COLLABORATION_ARTIFACTS",
    "MAX_COLLABORATION_FACTS",
    "MAX_SHARED_ARTIFACT_BYTES",
    "SHARED_ARTIFACT_REF_API_VERSION",
    "CollaborationSnapshot",
    "CollaborationSnapshotError",
    "SharedArtifactRef",
    "SharedArtifactRefError",
    "SharedArtifactSource",
    "create_collaboration_snapshot",
    "create_shared_artifact_ref",
    "verify_collaboration_snapshot",
    "verify_shared_artifact_ref",
]
