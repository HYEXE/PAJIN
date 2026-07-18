from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.exc import DatabaseError

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import CheckpointRecord, EventRecord, JobRecord
from pajin.control_plane.models import Principal, PrincipalRole

OPERATOR_TOKEN = "operator-token-that-is-long-and-distinct"
APPROVER_TOKEN = "approver-token-that-is-long-and-distinct"
WORKER_TOKEN = "worker-token-that-is-long-and-distinct"


def _settings(path: Path) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{path.as_posix()}",
        credentials={
            OPERATOR_TOKEN: Principal(
                subject="alice-operator",
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            APPROVER_TOKEN: Principal(
                subject="bob-approver",
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            ),
            WORKER_TOKEN: Principal(
                subject="worker-service",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"test-v1": b"test-checkpoint-signing-key-32-bytes-minimum"},
        active_checkpoint_key_id="test-v1",
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _submit(client: TestClient, suffix: str = "main") -> tuple[str, str]:
    response = client.post(
        "/v1/runs",
        headers=_auth(OPERATOR_TOKEN),
        json={
            "campaign_name": "control-plane-lab",
            "input": {"objective": "authorized validation"},
            "idempotency_key": f"control-plane-{suffix}",
            "max_attempts": 3,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return str(body["run"]["run_id"]), str(body["job"]["job_id"])


def _claim(client: TestClient, worker_id: str = "worker-1") -> dict[str, object]:
    response = client.post(
        "/v1/worker/jobs/claim",
        headers=_auth(WORKER_TOKEN),
        json={"worker_id": worker_id, "kinds": ["campaign"], "lease_seconds": 30},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _checkpoint(
    client: TestClient,
    job_id: str,
    lease_token: str,
    *,
    fingerprint: str = "a" * 64,
) -> dict[str, object]:
    response = client.post(
        f"/v1/worker/jobs/{job_id}/checkpoints",
        headers=_auth(WORKER_TOKEN),
        json={
            "worker_id": "worker-1",
            "lease_token": lease_token,
            "state": {"turn": 4, "messages": ["bounded state"]},
            "pending_intent": {
                "call_fingerprint": fingerprint,
                "tool_id": "mock.approval-probe",
                "target": "lab://approval-check",
                "risk_tier": 3,
                "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
            },
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_artifact_repository_environment_requires_both_roots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "test-checkpoint-signing-key-32-bytes-minimum",
    )
    monkeypatch.setenv("PAJIN_CP_ARTIFACT_STAGING_ROOT", "/tmp/pajin-staging")

    with pytest.raises(RuntimeError, match="must be configured together"):
        ControlPlaneSettings.from_env()


def test_artifact_repository_environment_loads_private_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "test-checkpoint-signing-key-32-bytes-minimum",
    )
    staging_root = tmp_path / "staging"
    repository_root = tmp_path / "repository"
    monkeypatch.setenv("PAJIN_CP_ARTIFACT_STAGING_ROOT", str(staging_root))
    monkeypatch.setenv("PAJIN_CP_ARTIFACT_REPOSITORY_ROOT", str(repository_root))

    settings = ControlPlaneSettings.from_env()

    assert settings.artifact_staging_root == staging_root
    assert settings.artifact_repository_root == repository_root


def test_create_app_rejects_partial_artifact_repository_configuration(
    tmp_path: Path,
) -> None:
    settings = replace(
        _settings(tmp_path / "control-plane.db"),
        artifact_staging_root=tmp_path / "staging",
    )

    with pytest.raises(RuntimeError, match="must be configured together"):
        create_app(settings)


def test_authenticated_submit_approval_resume_and_completion(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "control-plane.db"))
    with TestClient(app) as client:
        unauthorized = client.post(
            "/v1/runs",
            json={
                "campaign_name": "control-plane-lab",
                "idempotency_key": "missing-auth-key",
            },
        )
        assert unauthorized.status_code == 401

        run_id, job_id = _submit(client)
        duplicate = client.post(
            "/v1/runs",
            headers=_auth(OPERATOR_TOKEN),
            json={
                "campaign_name": "control-plane-lab",
                "input": {"ignored": "on-idempotent-replay"},
                "idempotency_key": "control-plane-main",
            },
        )
        assert duplicate.status_code == 200
        assert duplicate.json()["created"] is False
        assert duplicate.json()["run"]["run_id"] == run_id

        claimed = _claim(client)
        assert claimed["job"]["job_id"] == job_id
        lease_token = str(claimed["lease_token"])
        heartbeat = client.post(
            f"/v1/worker/jobs/{job_id}/heartbeat",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "worker-1",
                "lease_token": lease_token,
                "lease_seconds": 45,
            },
        )
        assert heartbeat.status_code == 200

        created = _checkpoint(client, job_id, lease_token)
        checkpoint_id = str(created["checkpoint"]["checkpoint_id"])
        approval_id = str(created["approval"]["approval_id"])
        assert created["approval"]["state"] == "pending"

        wrong_role = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=_auth(OPERATOR_TOKEN),
            json={"approve": True, "reason": "operator cannot self-approve"},
        )
        assert wrong_role.status_code == 403

        approved = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=_auth(APPROVER_TOKEN),
            json={"approve": True, "reason": "authorized lab scope verified"},
        )
        assert approved.status_code == 200
        assert approved.json()["decided_by"] == "bob-approver"

        worker_cannot_resume = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume",
            headers=_auth(WORKER_TOKEN),
            json={"approval_id": approval_id},
        )
        assert worker_cannot_resume.status_code == 403

        resumed = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume",
            headers=_auth(OPERATOR_TOKEN),
            json={"approval_id": approval_id},
        )
        assert resumed.status_code == 200, resumed.text
        assert resumed.json()["approval"]["state"] == "consumed"
        continuation_job_id = str(resumed.json()["job"]["job_id"])

        replay = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume",
            headers=_auth(OPERATOR_TOKEN),
            json={"approval_id": approval_id},
        )
        assert replay.status_code == 409
        assert "already been claimed" in replay.json()["detail"]

        continuation = _claim(client, worker_id="worker-2")
        assert continuation["job"]["job_id"] == continuation_job_id
        completion_payload = {
            "worker_id": "worker-2",
            "lease_token": continuation["lease_token"],
            "result": {"status": "validated"},
        }
        completed = client.post(
            f"/v1/worker/jobs/{continuation_job_id}/complete",
            headers=_auth(WORKER_TOKEN),
            json=completion_payload,
        )
        assert completed.status_code == 200
        repeated_completion = client.post(
            f"/v1/worker/jobs/{continuation_job_id}/complete",
            headers=_auth(WORKER_TOKEN),
            json=completion_payload,
        )
        assert repeated_completion.status_code == 200

        run = client.get(f"/v1/runs/{run_id}", headers=_auth(OPERATOR_TOKEN))
        assert run.json()["state"] == "completed"
        events = client.get(f"/v1/runs/{run_id}/events", headers=_auth(APPROVER_TOKEN)).json()
        assert [item["sequence"] for item in events] == list(range(1, len(events) + 1))
        assert "approval.approved" in {item["event_type"] for item in events}
        assert "checkpoint.claimed" in {item["event_type"] for item in events}


def test_expired_lease_is_requeued_and_old_token_is_rejected(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "crash-recovery.db"))
    with TestClient(app) as client:
        _run_id, job_id = _submit(client, "crash")
        first = _claim(client)
        first_token = str(first["lease_token"])

        repository = app.state.repository
        with repository.transaction() as session:
            session.execute(
                update(JobRecord)
                .where(JobRecord.job_id == job_id)
                .values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )

        swept = client.post("/v1/maintenance/requeue-expired", headers=_auth(OPERATOR_TOKEN))
        assert swept.status_code == 200
        assert swept.json()["requeuedOrDeadLettered"] == 1

        second = _claim(client, worker_id="worker-2")
        assert second["job"]["attempts"] == 2
        assert second["lease_token"] != first_token
        stale = client.post(
            f"/v1/worker/jobs/{job_id}/heartbeat",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "worker-1",
                "lease_token": first_token,
                "lease_seconds": 30,
            },
        )
        assert stale.status_code == 409


def test_tampered_checkpoint_and_event_mutation_are_blocked(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "integrity.db"))
    with TestClient(app) as client:
        run_id, job_id = _submit(client, "tamper")
        claimed = _claim(client)
        created = _checkpoint(client, job_id, str(claimed["lease_token"]), fingerprint="b" * 64)
        checkpoint_id = str(created["checkpoint"]["checkpoint_id"])
        approval_id = str(created["approval"]["approval_id"])
        approved = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=_auth(APPROVER_TOKEN),
            json={"approve": True, "reason": "approved before tampering"},
        )
        assert approved.status_code == 200

        repository = app.state.repository
        with repository.transaction() as session:
            checkpoint = session.scalar(
                select(CheckpointRecord).where(CheckpointRecord.checkpoint_id == checkpoint_id)
            )
            assert checkpoint is not None
            checkpoint.payload = {
                **checkpoint.payload,
                "state": {"turn": 999, "tampered": True},
            }

        resume = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume",
            headers=_auth(OPERATOR_TOKEN),
            json={"approval_id": approval_id},
        )
        assert resume.status_code == 409
        assert "integrity" in resume.json()["detail"]

        with (
            pytest.raises(DatabaseError, match="append-only"),
            repository.transaction() as session,
        ):
            event = session.scalar(select(EventRecord).where(EventRecord.run_id == run_id).limit(1))
            assert event is not None
            event.event_type = "event.tampered"


def test_lease_token_is_stored_only_as_a_digest(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "lease-secret.db"))
    with TestClient(app) as client:
        _run_id, job_id = _submit(client, "lease-secret")
        claimed = _claim(client)
        raw_token = str(claimed["lease_token"])
        with app.state.repository.transaction() as session:
            job = session.scalar(select(JobRecord).where(JobRecord.job_id == job_id))
            assert job is not None
            assert job.lease_token_hash is not None
            assert job.lease_token_hash != raw_token
            assert raw_token not in repr(job.payload)


def test_worker_claim_uses_bounded_long_poll(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "long-poll.db"))
    with TestClient(app) as client:
        started = monotonic()
        response = client.post(
            "/v1/worker/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "worker-long-poll",
                "kinds": ["campaign"],
                "lease_seconds": 30,
                "wait_seconds": 1,
            },
        )
        elapsed = monotonic() - started

    assert response.status_code == 204
    assert 0.9 <= elapsed < 2
