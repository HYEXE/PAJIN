"""Append-only publication of trusted Surface projections."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from pajin.discovery.admission import (
    SurfaceAdmissionError,
    TrustedSurfaceAdmission,
)
from pajin.runtime.store import (
    RunIntegritySeal,
    RunIntegrityVerification,
    RunStore,
    SealedArtifact,
    verify_run_integrity,
)


class SurfaceProjectionConflict(SurfaceAdmissionError):
    """Raised when a content-addressed Surface projection already exists."""


@dataclass(frozen=True, slots=True)
class SurfaceProjectionPublication:
    """Verified receipt for one append-only Surface Set publication."""

    projection_run_id: str
    projection_root_digest: str
    source_run_id: str
    source_root_digest: str
    surface_set_id: str
    artifact_path: str
    artifact_sha256: str


def publish_surface_projection(
    store: RunStore,
    admission: TrustedSurfaceAdmission,
) -> SurfaceProjectionPublication:
    """Publish one trusted admission without mutating its immutable source Run."""

    if not isinstance(store, RunStore):
        raise TypeError("Surface projection publication requires a RunStore")
    if not isinstance(admission, TrustedSurfaceAdmission):
        raise SurfaceAdmissionError("Surface projection requires trusted admission authority")
    admission.require_valid_authority()
    source = _verify_source(admission)
    _require_separate_projection_store(store, admission.source_run_path, source)

    surface_set = admission.surface_set
    identity_digest = surface_set.surface_set_id.removeprefix("attack-surface-set_")
    relative_path = f"discovery/surface-sets/{identity_digest[:32]}.json"
    if store.artifact_exists(relative_path):
        raise SurfaceProjectionConflict("Surface projection already exists")
    try:
        artifact_path = store.write_json_create_only(
            relative_path,
            surface_set.model_dump(mode="json", by_alias=True),
        )
    except FileExistsError as exc:
        raise SurfaceProjectionConflict("Surface projection already exists") from exc
    event_payload: dict[str, object] = {
        "producerId": admission.producer_id,
        "sourceToolId": admission.source_tool_spec.tool_id,
        "sourceToolVersion": admission.source_tool_spec.version,
        "sourceRunId": source.run_id,
        "sourceRootDigest": source.root_digest,
        "sourceEvidence": admission.evidence_reference,
        "surfaceSetId": surface_set.surface_set_id,
        "surfaceCount": len(surface_set.surfaces),
        "observationCount": len(surface_set.observations),
        "requestIds": sorted(
            {observation.request_id for observation in surface_set.observations}
        ),
        "artifact": artifact_path,
        "surfaceSetJsonSha256": sha256(
            surface_set.model_dump_json(by_alias=True).encode("utf-8")
        ).hexdigest(),
    }
    if admission.adapter_reference is not None:
        event_payload.update(
            {
                "adapterId": admission.adapter_reference.adapter_id,
                "adapterVersion": admission.adapter_reference.adapter_version,
                "adapterDigest": admission.adapter_reference.adapter_digest,
            }
        )
    store.append_event(
        "discovery.attack-surface-set.published",
        event_payload,
    )
    seal = store.seal()
    artifact = _published_artifact(seal, artifact_path)
    projection = verify_run_integrity(store.path)
    return SurfaceProjectionPublication(
        projection_run_id=projection.run_id,
        projection_root_digest=projection.root_digest,
        source_run_id=source.run_id,
        source_root_digest=source.root_digest,
        surface_set_id=surface_set.surface_set_id,
        artifact_path=artifact.path,
        artifact_sha256=artifact.sha256,
    )


def _verify_source(admission: TrustedSurfaceAdmission) -> RunIntegrityVerification:
    try:
        verification = verify_run_integrity(admission.source_run_path)
    except Exception as exc:
        raise SurfaceAdmissionError("trusted Surface source Run is no longer valid") from exc
    if verification != admission.source_verification:
        raise SurfaceAdmissionError("trusted Surface source Run changed after admission")
    return verification


def _require_separate_projection_store(
    store: RunStore,
    source_path: Path,
    source: RunIntegrityVerification,
) -> None:
    projection_path = store.path.resolve()
    source_path = source_path.resolve()
    if (
        store.run_id == source.run_id
        or projection_path == source_path
        or projection_path in source_path.parents
        or source_path in projection_path.parents
    ):
        raise SurfaceAdmissionError("Surface projection store must be separate from its source Run")


def _published_artifact(seal: RunIntegritySeal, path: str) -> SealedArtifact:
    matches = [artifact for artifact in seal.artifacts if artifact.path == path]
    if len(matches) != 1:
        raise SurfaceAdmissionError("Surface projection artifact was not sealed exactly once")
    return matches[0]
