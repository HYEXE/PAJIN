from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select

from pajin.control_plane.abac import (
    ControlPlaneReplaySourceArtifactABACPolicy,
    ControlPlaneReplaySourceArtifactAuthorizer,
    ReplaySourceArtifactAdmissionRule,
    parse_replay_source_artifact_abac_policy,
)
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.artifacts import ManagedArtifactSnapshot
from pajin.control_plane.database import (
    ArtifactRecord,
    EventRecord,
    JobRecord,
    RunRecord,
)
from pajin.control_plane.errors import AuthorizationDenied
from pajin.control_plane.models import (
    SOURCE_ARTIFACT_MEDIA_TYPE,
    SOURCE_ARTIFACT_SCHEMA_KIND,
    AdmitSourceArtifactRequest,
    ArtifactRef,
    JobKind,
    JobState,
    Principal,
    PrincipalRole,
    RunState,
    job_submission_authority_digest,
    non_replayable_submission_authority_digest,
    source_artifact_admission_authority_digest,
)

_OPERATOR_TOKEN = "source-artifact-abac-operator-token-that-is-long-and-distinct"
_OTHER_OPERATOR_TOKEN = "source-artifact-abac-other-operator-token-that-is-long-and-distinct"
_APPROVER_TOKEN = "source-artifact-abac-approver-token-that-is-long-and-distinct"
_WORKER_TOKEN = "source-artifact-abac-worker-token-that-is-long-and-distinct"
_OPERATOR_SUBJECT = "source-artifact-abac-operator"
_OTHER_OPERATOR_SUBJECT = "source-artifact-abac-other-operator"


class _FakeManagedArtifactRepository:
    def __init__(self, snapshot: ManagedArtifactSnapshot) -> None:
        self.snapshot = snapshot
        self.import_count = 0
        self.resolve_count = 0
        self.consume_count = 0

    def import_run(self, **_: object) -> ManagedArtifactSnapshot:
        self.import_count += 1
        return self.snapshot

    def resolve(self, ref: ArtifactRef) -> ManagedArtifactSnapshot:
        self.resolve_count += 1
        assert ref == self.snapshot.ref
        return self.snapshot

    def consume_staged_run(self, *, staging_id: str, expected_ref: ArtifactRef) -> bool:
        self.consume_count += 1
        assert staging_id.startswith("stage_")
        assert expected_ref == self.snapshot.ref
        return True


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _request(**updates: str) -> AdmitSourceArtifactRequest:
    values = {
        "staging_id": f"stage_{'1' * 32}",
        "producer_run_id": f"run_{'2' * 32}",
        "producer_job_id": f"job_{'3' * 32}",
        "idempotency_key": "source-artifact-abac-exact",
    }
    values.update(updates)
    return AdmitSourceArtifactRequest.model_validate(values)


def _policy(
    request: AdmitSourceArtifactRequest,
    *,
    subject: str = _OPERATOR_SUBJECT,
) -> ControlPlaneReplaySourceArtifactABACPolicy:
    digest = source_artifact_admission_authority_digest(request, actor=subject)
    return ControlPlaneReplaySourceArtifactABACPolicy(
        policy_id="replay-source-artifact-policy_0123456789abcdef0123456789abcdef",
        replay_source_artifact_admission_rules=(
            ReplaySourceArtifactAdmissionRule(
                principal_subject=subject,
                action="replay.source-artifact.admit",
                source_artifact_admission_authority_digest=digest,
            ),
        ),
    )


def _settings(
    tmp_path: Path,
    policy: ControlPlaneReplaySourceArtifactABACPolicy,
) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{(tmp_path / 'control-plane.db').as_posix()}",
        credentials={
            _OPERATOR_TOKEN: Principal(
                subject=_OPERATOR_SUBJECT,
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            _OTHER_OPERATOR_TOKEN: Principal(
                subject=_OTHER_OPERATOR_SUBJECT,
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            _APPROVER_TOKEN: Principal(
                subject="source-artifact-abac-approver",
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            ),
            _WORKER_TOKEN: Principal(
                subject="source-artifact-abac-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"source-artifact-abac-checkpoint-key-that-is-long-enough"},
        replay_source_artifact_abac_policy=policy,
        artifact_staging_root=tmp_path / "staging",
        artifact_repository_root=tmp_path / "repository",
    )


def _seed_producer(app: Any, request: AdmitSourceArtifactRequest) -> ArtifactRef:
    sealed_run_id = "engine_source_artifact_abac"
    now = datetime.now(UTC)
    payload = {"input": {}}
    job_key = "source-artifact-abac-producer-job"
    with app.state.repository.transaction() as session:
        session.add(
            RunRecord(
                run_id=request.producer_run_id,
                campaign_name="source-artifact-abac",
                state=RunState.COMPLETED.value,
                input={"source": "exact"},
                submission_key="source-artifact-abac-producer-run",
                submission_authority_digest=non_replayable_submission_authority_digest(
                    run_id=request.producer_run_id,
                    authority_kind="source-artifact-abac-fixture",
                ),
                current_checkpoint_id=None,
                created_at=now,
                updated_at=now,
            )
        )
        session.flush()
        session.add(
            JobRecord(
                job_id=request.producer_job_id,
                run_id=request.producer_run_id,
                kind=JobKind.CAMPAIGN.value,
                state=JobState.SUCCEEDED.value,
                payload=payload,
                priority=0,
                attempts=1,
                max_attempts=3,
                idempotency_key=job_key,
                submission_authority_digest=job_submission_authority_digest(
                    job_id=request.producer_job_id,
                    run_id=request.producer_run_id,
                    job_kind=JobKind.CAMPAIGN.value,
                    payload=payload,
                    max_attempts=3,
                    idempotency_key=job_key,
                ),
                available_at=now,
                lease_owner=None,
                lease_token_hash=None,
                lease_expires_at=None,
                heartbeat_at=None,
                result={"engineRunId": sealed_run_id},
                error=None,
                created_at=now,
                updated_at=now,
            )
        )
    return ArtifactRef(
        artifact_id=f"artifact_{'4' * 32}",
        repository_version=1,
        media_type=SOURCE_ARTIFACT_MEDIA_TYPE,
        schema_kind=SOURCE_ARTIFACT_SCHEMA_KIND,
        byte_length=1,
        content_digest="5" * 64,
        producer_run_id=request.producer_run_id,
        run_id=sealed_run_id,
        integrity_root_digest="6" * 64,
        created_by=_OPERATOR_SUBJECT,
    )


def _durable_counts(app: Any) -> tuple[int, int]:
    with app.state.repository.read_transaction() as session:
        artifacts = session.scalar(select(func.count()).select_from(ArtifactRecord))
        events = session.scalar(
            select(func.count())
            .select_from(EventRecord)
            .where(EventRecord.event_type == "artifact.source-admitted")
        )
    return int(artifacts or 0), int(events or 0)


def test_replay_source_artifact_policy_is_strict_and_exact() -> None:
    request = _request()
    policy = _policy(request)
    exact_rule = policy.replay_source_artifact_admission_rules[0]
    with pytest.raises(ValidationError, match="admission rules must be unique"):
        ControlPlaneReplaySourceArtifactABACPolicy(
            policy_id="replay-source-artifact-policy_0123456789abcdef0123456789abcdef",
            replay_source_artifact_admission_rules=(exact_rule, exact_rule),
        )
    raw = policy.model_dump(mode="json")
    raw["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_replay_source_artifact_abac_policy(json.dumps(raw).encode("utf-8"))

    authorizer = ControlPlaneReplaySourceArtifactAuthorizer(policy)
    with pytest.raises(AuthorizationDenied, match="source Artifact admission"):
        authorizer.authorize_replay_source_artifact_admission(
            principal_subject=_OPERATOR_SUBJECT,
            source_artifact_admission_authority_digest="f" * 64,
        )


def test_replay_source_artifact_rules_must_name_authenticated_operators(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="authenticated Operator subjects"):
        _settings(tmp_path, _policy(_request(), subject="unknown-operator"))


def test_environment_loads_replay_source_artifact_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(_request())
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", _OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_OPERATOR_SUBJECT", _OPERATOR_SUBJECT)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", _APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", _WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "source-artifact-abac-checkpoint-key-that-is-long-enough",
    )
    monkeypatch.setenv(
        "PAJIN_CP_REPLAY_SOURCE_ARTIFACT_ABAC_POLICY",
        policy.model_dump_json(),
    )
    for name in (
        "PAJIN_CP_ABAC_POLICY",
        "PAJIN_CP_RUN_SUBMISSION_ABAC_POLICY",
        "PAJIN_CP_RUN_CANCELLATION_ABAC_POLICY",
        "PAJIN_CP_CHECKPOINT_RESUME_ABAC_POLICY",
        "PAJIN_CP_OIDC_HUMAN_TRUST_POLICY",
        "PAJIN_CP_WORKER_MTLS_TRUST_POLICY",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = ControlPlaneSettings.from_env()

    assert settings.replay_source_artifact_abac_policy == policy


def test_exact_source_artifact_admission_and_idempotent_retry_are_authorized(
    tmp_path: Path,
) -> None:
    request = _request()
    app = create_app(_settings(tmp_path, _policy(request)))
    with TestClient(app) as client:
        ref = _seed_producer(app, request)
        fake_repository = _FakeManagedArtifactRepository(
            ManagedArtifactSnapshot(
                ref=ref,
                storage_key="objects/source-artifact-abac",
                path=tmp_path / "managed-object",
            )
        )
        app.state.control_plane._artifact_repository = fake_repository

        first = client.post(
            "/v1/replay/source-artifacts",
            headers=_auth(_OPERATOR_TOKEN),
            json=request.model_dump(mode="json"),
        )
        repeat = client.post(
            "/v1/replay/source-artifacts",
            headers=_auth(_OPERATOR_TOKEN),
            json=request.model_dump(mode="json"),
        )
        denied_repeat = client.post(
            "/v1/replay/source-artifacts",
            headers=_auth(_OTHER_OPERATOR_TOKEN),
            json=request.model_dump(mode="json"),
        )
        counts = _durable_counts(app)

    assert first.status_code == 200, first.text
    assert repeat.status_code == 200, repeat.text
    assert repeat.json() == first.json()
    assert denied_repeat.status_code == 403
    assert denied_repeat.json() == {
        "detail": "ABAC policy denied the Replay source Artifact admission"
    }
    assert counts == (1, 1)
    assert fake_repository.import_count == 1
    assert fake_repository.resolve_count == 1
    assert fake_repository.consume_count == 2


@pytest.mark.parametrize(
    "updates",
    [
        {"staging_id": f"stage_{'a' * 32}"},
        {"producer_run_id": f"run_{'b' * 32}"},
        {"producer_job_id": f"job_{'c' * 32}"},
        {"idempotency_key": "source-artifact-abac-substituted"},
    ],
    ids=["staging", "producer-run", "producer-job", "idempotency"],
)
def test_mismatched_source_artifact_authority_denies_before_import_or_mutation(
    tmp_path: Path,
    updates: dict[str, str],
) -> None:
    allowed = _request()
    attempted = _request(**updates)
    app = create_app(_settings(tmp_path, _policy(allowed)))
    with TestClient(app) as client:
        app.state.control_plane._artifact_repository = None
        response = client.post(
            "/v1/replay/source-artifacts",
            headers=_auth(_OPERATOR_TOKEN),
            json=attempted.model_dump(mode="json"),
        )
        counts = _durable_counts(app)

    assert response.status_code == 403
    assert response.json() == {"detail": "ABAC policy denied the Replay source Artifact admission"}
    assert counts == (0, 0)
