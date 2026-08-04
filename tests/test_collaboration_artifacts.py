from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.collaboration import (
    MAX_SHARED_ARTIFACT_BYTES,
    SharedArtifactRef,
    SharedArtifactRefError,
    create_shared_artifact_ref,
    verify_shared_artifact_ref,
)
from pajin.domain.models import CampaignManifest
from pajin.graph import GraphEvidence
from pajin.runtime.store import (
    RunStore,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
ARTIFACT_PATH = "evidence/shared-fact.json"
ARTIFACT_BYTES = b'{"fact":"bounded collaboration evidence"}\n'


def _sealed_source(
    tmp_path: Path,
    campaign: CampaignManifest,
    *,
    run_id: str | None = None,
    artifact_path: str = ARTIFACT_PATH,
    content: bytes = ARTIFACT_BYTES,
) -> RunStore:
    store = RunStore.create(
        tmp_path / "runs",
        campaign.metadata.name,
        run_id=run_id,
    )
    store.append_event(
        "campaign.started",
        {"campaign": campaign.metadata.name, "mode": campaign.spec.mode.value},
        occurred_at=NOW,
    )
    store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))
    store.write_bytes(artifact_path, content)
    store.seal()
    return store


def _evidence(
    store: RunStore,
    campaign_id: str,
    *,
    artifact_path: str = ARTIFACT_PATH,
    content: bytes = ARTIFACT_BYTES,
    media_type: str = "application/json",
) -> GraphEvidence:
    snapshot = load_verified_run_snapshot(store.path, expected_run_id=store.run_id)
    return GraphEvidence(
        campaignId=campaign_id,
        reference=artifact_path,
        sha256=sha256(content).hexdigest(),
        mediaType=media_type,
        sourceRootDigest=snapshot.verification.root_digest,
        dataClassification="internal",
    )


def test_shared_artifact_ref_binds_existing_graph_evidence_and_sealed_metadata_only(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    evidence = _evidence(source, sample_campaign.metadata.name)

    reference = create_shared_artifact_ref(evidence, source_run_path=source.path)
    retry = create_shared_artifact_ref(evidence, source_run_path=source.path)
    verified = verify_shared_artifact_ref(
        reference,
        evidence,
        source_run_path=source.path,
    )

    assert retry == reference == verified
    assert reference.campaign_id == sample_campaign.metadata.name
    assert reference.evidence.node_id == evidence.node_id
    assert reference.source_run_id == source.run_id
    assert reference.source_root_digest == evidence.source_root_digest
    assert reference.relative_path == ARTIFACT_PATH
    assert reference.sha256 == sha256(ARTIFACT_BYTES).hexdigest()
    assert reference.media_type == "application/json"
    assert reference.size_bytes == len(ARTIFACT_BYTES)
    serialized = reference.model_dump(mode="json", by_alias=True)
    assert {
        "content",
        "contentBase64",
        "prompt",
        "messages",
        "scope",
        "capability",
        "toolRequest",
        "filesystemPath",
    }.isdisjoint(serialized)
    assert serialized["contentEmbedded"] is False
    assert serialized["promptRelayAuthorized"] is False
    assert serialized["receiverAuthorityGranted"] is False
    assert serialized["scopeExpansionAuthorized"] is False
    assert serialized["capabilityGranted"] is False
    assert serialized["executionAuthorized"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sha256", "f" * 64),
        ("sizeBytes", len(ARTIFACT_BYTES) + 1),
        ("mediaType", "text/plain"),
    ],
)
def test_forged_digest_size_or_media_type_fails_against_sealed_record(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    field: str,
    value: object,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    evidence = _evidence(source, sample_campaign.metadata.name)
    reference = create_shared_artifact_ref(evidence, source_run_path=source.path)
    raw = reference.model_dump(mode="json", by_alias=True)
    raw[field] = value
    raw["sharedArtifactId"] = ""
    raw["sharedArtifactDigest"] = ""
    forged = SharedArtifactRef.model_validate(raw)

    with pytest.raises(SharedArtifactRefError):
        verify_shared_artifact_ref(forged, evidence, source_run_path=source.path)


def test_path_traversal_and_authority_flag_forgery_fail_at_wire_boundary(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    evidence = _evidence(source, sample_campaign.metadata.name)
    reference = create_shared_artifact_ref(evidence, source_run_path=source.path)
    raw = reference.model_dump(mode="json", by_alias=True)
    raw["relativePath"] = "../operator-secret.txt"
    raw["sharedArtifactId"] = ""
    raw["sharedArtifactDigest"] = ""
    with pytest.raises(ValidationError, match="normalized relative path"):
        SharedArtifactRef.model_validate(raw)

    for field in (
        "contentEmbedded",
        "promptRelayAuthorized",
        "receiverAuthorityGranted",
        "scopeExpansionAuthorized",
        "capabilityGranted",
        "executionAuthorized",
    ):
        for forged_value in (True, 0, "false"):
            raw = reference.model_dump(mode="json", by_alias=True)
            raw[field] = forged_value
            with pytest.raises(ValidationError):
                SharedArtifactRef.model_validate(raw)


def test_cross_campaign_and_cross_run_substitution_fail_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    evidence = _evidence(source, sample_campaign.metadata.name)
    reference = create_shared_artifact_ref(evidence, source_run_path=source.path)

    foreign_campaign = sample_campaign.model_copy(deep=True)
    foreign_campaign.metadata.name = "foreign-campaign"
    foreign = _sealed_source(
        tmp_path / "foreign",
        foreign_campaign,
        run_id=source.run_id,
    )
    with pytest.raises(SharedArtifactRefError):
        verify_shared_artifact_ref(reference, evidence, source_run_path=foreign.path)

    other_run = _sealed_source(tmp_path / "other", sample_campaign)
    with pytest.raises(SharedArtifactRefError):
        verify_shared_artifact_ref(reference, evidence, source_run_path=other_run.path)


def test_stale_root_mutation_missing_and_oversized_artifact_fail_closed(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    stale_source = _sealed_source(tmp_path / "stale", sample_campaign)
    stale_evidence = _evidence(stale_source, sample_campaign.metadata.name)
    stale_reference = create_shared_artifact_ref(
        stale_evidence,
        source_run_path=stale_source.path,
    )
    stale_source.append_event("campaign.extended", {"reason": "new sealed state"})
    stale_source.seal()
    with pytest.raises(SharedArtifactRefError):
        verify_shared_artifact_ref(
            stale_reference,
            stale_evidence,
            source_run_path=stale_source.path,
        )

    mutated_source = _sealed_source(tmp_path / "mutated", sample_campaign)
    mutated_evidence = _evidence(mutated_source, sample_campaign.metadata.name)
    mutated_reference = create_shared_artifact_ref(
        mutated_evidence,
        source_run_path=mutated_source.path,
    )
    (mutated_source.path / ARTIFACT_PATH).write_bytes(b'{"fact":"substituted"}\n')
    with pytest.raises(SharedArtifactRefError):
        verify_shared_artifact_ref(
            mutated_reference,
            mutated_evidence,
            source_run_path=mutated_source.path,
        )

    missing_source = _sealed_source(tmp_path / "missing", sample_campaign)
    missing_evidence = _evidence(missing_source, sample_campaign.metadata.name)
    missing_reference = create_shared_artifact_ref(
        missing_evidence,
        source_run_path=missing_source.path,
    )
    (missing_source.path / ARTIFACT_PATH).unlink()
    with pytest.raises(SharedArtifactRefError):
        verify_shared_artifact_ref(
            missing_reference,
            missing_evidence,
            source_run_path=missing_source.path,
        )

    oversized = b"x" * (MAX_SHARED_ARTIFACT_BYTES + 1)
    oversized_source = _sealed_source(
        tmp_path / "oversized",
        sample_campaign,
        content=oversized,
    )
    oversized_evidence = _evidence(
        oversized_source,
        sample_campaign.metadata.name,
        content=oversized,
    )
    with pytest.raises(SharedArtifactRefError):
        create_shared_artifact_ref(
            oversized_evidence,
            source_run_path=oversized_source.path,
        )


def test_symlink_substitution_fails_when_platform_can_create_test_link(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    evidence = _evidence(source, sample_campaign.metadata.name)
    reference = create_shared_artifact_ref(evidence, source_run_path=source.path)
    artifact_path = source.path / ARTIFACT_PATH
    victim = tmp_path / "operator-secret.json"
    victim.write_bytes(ARTIFACT_BYTES)
    artifact_path.unlink()
    try:
        artifact_path.symlink_to(victim)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")

    with pytest.raises(SharedArtifactRefError):
        verify_shared_artifact_ref(reference, evidence, source_run_path=source.path)


def test_same_reference_is_deterministic_and_equivocal_identity_is_rejected(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    evidence = _evidence(source, sample_campaign.metadata.name)
    first = create_shared_artifact_ref(evidence, source_run_path=source.path)
    second = create_shared_artifact_ref(evidence, source_run_path=source.path)
    assert first.shared_artifact_id == second.shared_artifact_id
    assert first.shared_artifact_digest == second.shared_artifact_digest

    raw = first.model_dump(mode="json", by_alias=True)
    raw["mediaType"] = "text/plain"
    with pytest.raises(ValidationError, match="canonical identity"):
        SharedArtifactRef.model_validate(raw)


def test_reference_rejects_campaign_manifest_as_shared_evidence(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    snapshot = load_verified_run_artifacts(
        source.path,
        requests={"campaign.json": 1024 * 1024},
        expected_run_id=source.run_id,
    )
    campaign_bytes = snapshot.artifact_bytes("campaign.json")
    evidence = GraphEvidence(
        campaignId=sample_campaign.metadata.name,
        reference="campaign.json",
        sha256=sha256(campaign_bytes).hexdigest(),
        mediaType="application/json",
        sourceRootDigest=snapshot.verification.root_digest,
        dataClassification="internal",
    )

    with pytest.raises(SharedArtifactRefError):
        create_shared_artifact_ref(evidence, source_run_path=source.path)
