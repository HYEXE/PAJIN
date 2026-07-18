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
from pajin.control_plane.models import (
    Principal,
    PrincipalRole,
    ReplayToolPermitRequest,
    ReplayToolPermitView,
)
from pajin.control_plane.service import LeaseRejected

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


def _set_required_control_plane_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "test-checkpoint-signing-key-32-bytes-minimum",
    )


def _replay_tool_permit_view() -> ReplayToolPermitView:
    issued_at = datetime.now(UTC)
    return ReplayToolPermitView(
        permit_id=f"replay-permit_{'8' * 32}",
        permit_digest="c" * 64,
        replay_request_id=f"tool_replay_{'9' * 32}",
        job_id=f"job_{'4' * 32}",
        batch_id=f"replay-batch_{'1' * 32}",
        item_id=f"replay-item_{'2' * 32}",
        ticket_id=f"replay-ticket_{'3' * 32}",
        compilation_id=f"replay-compilation_{'5' * 32}",
        budget_reservation_id=f"budget-reservation_{'6' * 32}",
        rate_reservation_id=f"rate-reservation_{'7' * 32}",
        replay_run_id="run_replay_transport",
        attempt=1,
        fencing_value=7,
        call_ordinal=1,
        issued_to="worker-service",
        executor_profile="kisa-exact-v1",
        source_root_digest="a" * 64,
        compilation_digest="e" * 64,
        grant_digest="f" * 64,
        original_request_id="tool_original_request",
        tool_id="ai.chat-probe",
        tool_version="1.0.0",
        target_id="target-ai-chat",
        target="http://127.0.0.1:8080/v1/chat",
        method="POST",
        compiled_argument_digest="b" * 64,
        tool_call_units=1,
        request_units=3,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=15),
    )


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


def test_replay_executor_profile_environment_is_explicit_and_subject_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_required_control_plane_environment(monkeypatch)
    monkeypatch.setenv("PAJIN_CP_WORKER_SUBJECT", "worker-service")
    monkeypatch.setenv(
        "PAJIN_CP_REPLAY_EXECUTOR_PROFILES",
        '{"worker-service":["kisa-exact-v1","kisa-exact-v2"]}',
    )

    settings = ControlPlaneSettings.from_env()

    assert settings.replay_executor_profiles == {
        "worker-service": frozenset({"kisa-exact-v1", "kisa-exact-v2"})
    }


@pytest.mark.parametrize(
    "raw_allowlist",
    [
        "",
        "[]",
        '{"unknown-worker":["kisa-exact-v1"]}',
        '{"worker-service":[]}',
        '{"worker-service":"kisa-exact-v1"}',
        '{"worker-service":["invalid profile"]}',
        '{"worker-service":["kisa-exact-v1","kisa-exact-v1"]}',
        ('{"worker-service":["kisa-exact-v1"],"worker-service":["kisa-exact-v2"]}'),
    ],
)
def test_replay_executor_profile_environment_rejects_ambiguous_authority(
    monkeypatch: pytest.MonkeyPatch,
    raw_allowlist: str,
) -> None:
    _set_required_control_plane_environment(monkeypatch)
    monkeypatch.setenv("PAJIN_CP_WORKER_SUBJECT", "worker-service")
    monkeypatch.setenv("PAJIN_CP_REPLAY_EXECUTOR_PROFILES", raw_allowlist)

    with pytest.raises(RuntimeError, match="PAJIN_CP_REPLAY_EXECUTOR_PROFILES"):
        ControlPlaneSettings.from_env()


def test_programmatic_replay_executor_profiles_reject_non_worker_subject(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="authenticated Worker principal"):
        replace(
            _settings(tmp_path / "invalid-replay-profile-subject.db"),
            replay_executor_profiles={"alice-operator": frozenset({"kisa-exact-v1"})},
        )


def test_replay_worker_routes_are_role_protected_typed_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty_app = create_app(_settings(tmp_path / "replay-route-fail-closed.db"))
    claim_body = {"executor_profile": "kisa-exact-v1", "lease_seconds": 30}
    with TestClient(empty_app) as client:
        rejected = client.post(
            "/v1/worker/replay/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json=claim_body,
        )
    assert rejected.status_code == 403
    assert rejected.json() == {
        "detail": "authenticated Worker principal is not registered for this Replay executor"
    }

    settings = replace(
        _settings(tmp_path / "replay-routes.db"),
        replay_executor_profiles={"worker-service": frozenset({"kisa-exact-v1"})},
    )
    app = create_app(settings)
    job_id = f"job_{'4' * 32}"
    ticket_id = f"replay-ticket_{'3' * 32}"
    lease_token = "lease-token-that-is-at-least-32-characters"
    permit_body = {
        "executor_profile": "kisa-exact-v1",
        "lease_token": lease_token,
        "ticket_id": ticket_id,
        "fencing_value": 7,
        "call_ordinal": 1,
    }
    seen: dict[str, object] = {}

    with TestClient(app) as client:
        missing_auth = client.post(
            "/v1/worker/replay/jobs/claim",
            json=claim_body,
        )
        wrong_role = client.post(
            "/v1/worker/replay/jobs/claim",
            headers=_auth(OPERATOR_TOKEN),
            json=claim_body,
        )
        empty_claim = client.post(
            "/v1/worker/replay/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json=claim_body,
        )

        def issue_permit(
            selected_job_id: str,
            request: ReplayToolPermitRequest,
            *,
            actor: str,
        ) -> ReplayToolPermitView:
            seen.update(job_id=selected_job_id, request=request, actor=actor)
            return _replay_tool_permit_view()

        monkeypatch.setattr(
            app.state.control_plane,
            "issue_replay_tool_permit",
            issue_permit,
        )
        issued = client.post(
            f"/v1/worker/replay/jobs/{job_id}/tool-permits",
            headers=_auth(WORKER_TOKEN),
            json=permit_body,
        )
        injected = client.post(
            f"/v1/worker/replay/jobs/{job_id}/tool-permits",
            headers=_auth(WORKER_TOKEN),
            json={**permit_body, "target": "https://attacker.invalid"},
        )

        def reject_heartbeat(*_args: object, **_kwargs: object) -> None:
            raise LeaseRejected("Replay job lease has expired")

        monkeypatch.setattr(
            app.state.control_plane,
            "heartbeat_replay_job",
            reject_heartbeat,
        )
        heartbeat = client.post(
            f"/v1/worker/replay/jobs/{job_id}/heartbeat",
            headers=_auth(WORKER_TOKEN),
            json={
                "executor_profile": "kisa-exact-v1",
                "lease_token": lease_token,
                "lease_seconds": 30,
                "ticket_id": ticket_id,
                "fencing_value": 7,
            },
        )
        openapi = client.get("/openapi.json").json()

    assert missing_auth.status_code == 401
    assert wrong_role.status_code == 403
    assert empty_claim.status_code == 204
    assert issued.status_code == 200, issued.text
    assert seen == {
        "job_id": job_id,
        "request": ReplayToolPermitRequest.model_validate(permit_body),
        "actor": "worker-service",
    }
    assert lease_token not in issued.text
    assert issued.headers["cache-control"] == "no-store, max-age=0"
    assert issued.headers["pragma"] == "no-cache"
    assert injected.status_code == 422
    assert heartbeat.status_code == 409
    assert heartbeat.json() == {
        "detail": "Replay job lease has expired",
        "code": "lease_lost",
    }

    replay_paths = (
        "/v1/worker/replay/jobs/claim",
        "/v1/worker/replay/jobs/{job_id}/heartbeat",
        "/v1/worker/replay/jobs/{job_id}/tool-permits",
    )
    paths = openapi["paths"]
    assert all(path in paths for path in replay_paths)
    assert all("409" in paths[path]["post"]["responses"] for path in replay_paths)
    assert all(not path.startswith("/v1/replay") for path in paths)
