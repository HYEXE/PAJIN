from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.models import (
    ArtifactRef,
    Principal,
    PrincipalRole,
    ReplayBatchState,
    ReplayBatchView,
    ReplayProjectionItemAuthority,
    ReplayProjectionView,
    ReplayRetestProjectionInputAuthority,
)
from pajin.control_plane.replay_comparison import (
    ReplayComparisonIntegrityError,
    VerifiedReplayEvidenceComparisonReader,
)
from pajin.control_plane.service import ControlPlaneService
from pajin.domain.replay import ReplayPurpose
from pajin.replay.tickets import replay_context_digest

NOW = datetime(2026, 8, 11, 9, 0, tzinfo=UTC)
BATCH_ID = f"replay-batch_{'1' * 32}"
OPERATOR_TOKEN = "replay-comparison-operator-token-long-enough"
APPROVER_TOKEN = "replay-comparison-approver-token-long-enough"
AUDITOR_TOKEN = "replay-comparison-auditor-token-long-enough"
WORKER_TOKEN = "replay-comparison-worker-token-long-enough"


def _artifact(tag: str, *, run_id: str) -> ArtifactRef:
    return ArtifactRef(
        artifact_id=f"artifact_{tag * 32}",
        repository_version=1,
        media_type="application/vnd.pajin.run+json",
        schema_kind="pajin.test.replay-comparison",
        byte_length=512,
        content_digest=tag * 64,
        producer_run_id=f"run_{tag * 32}",
        run_id=run_id,
        integrity_root_digest=(chr(ord(tag) + 1) * 64),
        created_by="sensitive-producer",
    )


def _projection() -> ReplayProjectionView:
    baseline = _artifact("1", run_id="baseline-run")
    retest_source = _artifact("3", run_id="parent-retest-run")
    output = _artifact("5", run_id="replay-run-1")
    item = ReplayProjectionItemAuthority(
        ordinal=0,
        item_id=f"replay-item_{'6' * 32}",
        ticket_id=f"replay-ticket_{'7' * 32}",
        finalization_id=f"replay-finalization_{'8' * 32}",
        replay_run_id="replay-run-1",
        compilation_digest="9" * 64,
        output=output,
        artifact_set_digest="a" * 64,
        receipt_seal_root_digest="b" * 64,
        gate_decision_digest="c" * 64,
        result_digest="d" * 64,
        finalized_at=NOW,
    )
    authority = ReplayRetestProjectionInputAuthority(
        batch_id=BATCH_ID,
        source=baseline,
        retest_source=retest_source,
        batch_cas_version=1,
        items=[item],
    )
    assessment = ArtifactRef(
        artifact_id=f"artifact_{'e' * 32}",
        repository_version=1,
        media_type="application/vnd.pajin.run+json",
        schema_kind="pajin.test.retest-assessment",
        byte_length=256,
        content_digest="e" * 64,
        producer_run_id=retest_source.producer_run_id,
        run_id=retest_source.run_id,
        integrity_root_digest="f" * 64,
        created_by="projection-publisher",
    )
    batch = ReplayBatchView(
        batch_id=BATCH_ID,
        campaign_name="replay-comparison-campaign",
        source=baseline,
        retest_source=retest_source,
        mode="ai-redteam",
        purpose=ReplayPurpose.REMEDIATION_RETEST,
        policy_version="kisa-retest-v1",
        state=ReplayBatchState.COMPLETED,
        cas_version=2,
        created_by="sensitive-operator",
        created_at=NOW,
        updated_at=NOW,
    )
    return ReplayProjectionView(
        projection_id=f"replay-projection_{'f' * 32}",
        batch=batch,
        artifact=assessment,
        input_authority=authority,
        input_authority_digest=replay_context_digest(
            authority.model_dump(mode="json", by_alias=True)
        ),
        published_by="projection-publisher",
        published_at=NOW,
    )


class _ProjectionReader:
    def __init__(self, projection: ReplayProjectionView | None) -> None:
        self.projection = projection

    def get_replay_projection(self, batch_id: str) -> ReplayProjectionView | None:
        assert batch_id == BATCH_ID
        return self.projection


def _settings(database: Path) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{database.as_posix()}",
        credentials={
            OPERATOR_TOKEN: Principal(
                subject="replay-comparison-operator",
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            APPROVER_TOKEN: Principal(
                subject="replay-comparison-approver",
                roles=frozenset({PrincipalRole.APPROVER}),
            ),
            AUDITOR_TOKEN: Principal(
                subject="replay-comparison-auditor",
                roles=frozenset({PrincipalRole.AUDITOR}),
            ),
            WORKER_TOKEN: Principal(
                subject="replay-comparison-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"replay-comparison-signing-key-32-bytes"},
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_replay_comparison_maps_only_exact_redacted_coordinates() -> None:
    view = VerifiedReplayEvidenceComparisonReader(_ProjectionReader(_projection())).read(
        batch_id=BATCH_ID
    )

    assert view.batch_id == BATCH_ID
    assert view.purpose is ReplayPurpose.REMEDIATION_RETEST
    assert tuple(lane.stage for lane in view.lanes) == (
        "original",
        "replay",
        "control",
        "retest",
    )
    assert view.lanes[0].authority_role == "remediation-baseline"
    assert view.lanes[1].run_ids == ("replay-run-1",)
    assert view.lanes[2].availability == "not-in-authority"
    assert view.lanes[2].run_ids == ()
    assert view.lanes[3].run_ids == ("parent-retest-run",)
    assert view.authority_boundary.control_evidence_included is False
    assert view.authority_boundary.semantic_evidence_compared is False
    serialized = view.model_dump_json(by_alias=True)
    assert "sensitive-producer" not in serialized
    assert "sensitive-operator" not in serialized
    assert "projection-publisher" not in serialized


def test_replay_comparison_rejects_cross_lane_lineage_reuse() -> None:
    projection = _projection()
    authority = projection.input_authority
    assert isinstance(authority, ReplayRetestProjectionInputAuthority)
    item = authority.items[0].model_copy(
        update={"replay_run_id": authority.source.run_id}
    )
    forged = authority.model_copy(update={"items": [item]})
    projection = projection.model_copy(update={"input_authority": forged})

    with pytest.raises(ReplayComparisonIntegrityError, match="integrity-valid"):
        VerifiedReplayEvidenceComparisonReader(_ProjectionReader(projection)).read(
            batch_id=BATCH_ID
        )


def test_replay_comparison_endpoint_is_operator_only_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = _projection()
    monkeypatch.setattr(
        ControlPlaneService,
        "get_replay_projection",
        lambda _service, batch_id: projection if batch_id == BATCH_ID else None,
    )
    app = create_app(_settings(tmp_path / "control-plane.sqlite3"))
    path = f"/v1/replay-comparisons/batches/{BATCH_ID}"

    with TestClient(app) as client:
        response = client.get(path, headers=_auth(OPERATOR_TOKEN))
        assert response.status_code == 200
        body = response.json()
        assert body["apiVersion"] == (
            "pajin.control-plane/verified-replay-evidence-comparison-view/v1alpha1"
        )
        assert body["comparisonMode"] == "exact-coordinates-no-semantic-diff"
        assert body["authorityBoundary"] == {
            "durableProjectionBindingVerified": True,
            "exactLineageCoordinatesVerified": True,
            "identifiersAndContentRedacted": True,
            "controlEvidenceIncluded": False,
            "semanticEvidenceCompared": False,
            "viewEvaluatesValidation": False,
            "viewAttestsRemediation": False,
            "viewConfirmsFinding": False,
            "viewAuthorizesExecution": False,
        }
        serialized = response.text
        assert "sensitive-producer" not in serialized
        assert "sensitive-operator" not in serialized
        assert "projection-publisher" not in serialized
        assert client.get(path).status_code == 401
        assert client.get(path, headers=_auth(APPROVER_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(AUDITOR_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(WORKER_TOKEN)).status_code == 403
        assert client.get(
            "/v1/replay-comparisons/batches/not-a-batch",
            headers=_auth(OPERATOR_TOKEN),
        ).status_code == 422
        assert client.get(
            f"/v1/replay-comparisons/batches/replay-batch_{'2' * 32}",
            headers=_auth(OPERATOR_TOKEN),
        ).status_code == 404
