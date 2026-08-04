"""Structured collaboration projections derived from existing PAJIN authorities."""

from pajin.collaboration.artifacts import (
    MAX_SHARED_ARTIFACT_BYTES,
    SHARED_ARTIFACT_REF_API_VERSION,
    SharedArtifactRef,
    SharedArtifactRefError,
    create_shared_artifact_ref,
    verify_shared_artifact_ref,
)

__all__ = [
    "MAX_SHARED_ARTIFACT_BYTES",
    "SHARED_ARTIFACT_REF_API_VERSION",
    "SharedArtifactRef",
    "SharedArtifactRefError",
    "create_shared_artifact_ref",
    "verify_shared_artifact_ref",
]
