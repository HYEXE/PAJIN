from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from pydantic import ValidationError
from sqlalchemy import func, select

from pajin.control_plane.abac import (
    CheckpointResumeRule,
    ControlPlaneCheckpointResumeABACPolicy,
    ControlPlaneCheckpointResumeAuthorizer,
    parse_checkpoint_resume_abac_policy,
)
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import (
    ApprovalRecord,
    CheckpointRecord,
    EventRecord,
    JobRecord,
    RunRecord,
)
from pajin.control_plane.errors import AuthorizationDenied
from pajin.control_plane.models import (
    ApprovalState,
    Principal,
    PrincipalRole,
    RunState,
    checkpoint_resume_authority_digest,
)

_OPERATOR_TOKEN = "resume-abac-operator-token-that-is-long-and-distinct"
_OTHER_OPERATOR_TOKEN = "resume-abac-other-operator-token-that-is-long-and-distinct"
_APPROVER_TOKEN = "resume-abac-approver-token-that-is-long-and-distinct"
_WORKER_TOKEN = "resume-abac-worker-token-that-is-long-and-distinct"
_OPERATOR_SUBJECT = "resume-abac-operator"
_OTHER_OPERATOR_SUBJECT = "resume-abac-other-operator"
_APPROVER_SUBJECT = "resume-abac-approver"
_WORKER_SUBJECT = "resume-abac-worker"
_CHECKPOINT_KEY = b"resume-abac-checkpoint-signing-key-that-is-long-enough"


@dataclass(frozen=True)
class _ApprovedCheckpoint:
    database_path: Path
    run_id: str
    checkpoint_id: str
    approval_id: str
    authority_material: dict[str, Any]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _policy(
    digest: str,
    *,
    subject: str = _OPERATOR_SUBJECT,
) -> ControlPlaneCheckpointResumeABACPolicy:
    return ControlPlaneCheckpointResumeABACPolicy(
        policy_id="checkpoint-resume-policy_0123456789abcdef0123456789abcdef",
        checkpoint_resume_rules=(
            CheckpointResumeRule(
                principal_subject=subject,
                action="checkpoint.resume",
                checkpoint_resume_authority_digest=digest,
            ),
        ),
    )


def _settings(
    database_path: Path,
    policy: ControlPlaneCheckpointResumeABACPolicy | None = None,
) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{database_path.as_posix()}",
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
                subject=_APPROVER_SUBJECT,
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            ),
            _WORKER_TOKEN: Principal(
                subject=_WORKER_SUBJECT,
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": _CHECKPOINT_KEY},
        checkpoint_resume_abac_policy=policy,
    )


def _prepare_approved_checkpoint(tmp_path: Path) -> _ApprovedCheckpoint:
    database_path = tmp_path / "control-plane.db"
    app = create_app(_settings(database_path))
    with TestClient(app) as client:
        submitted = client.post(
            "/v1/runs",
            headers=_auth(_OPERATOR_TOKEN),
            json={
                "campaign_name": "resume-abac-campaign",
                "input": {"objective": "resume only the exact signed checkpoint"},
                "idempotency_key": "resume-abac-submission",
                "max_attempts": 3,
            },
        )
        assert submitted.status_code == 200, submitted.text
        run_id = str(submitted.json()["run"]["run_id"])
        job_id = str(submitted.json()["job"]["job_id"])
        claimed = client.post(
            "/v1/worker/jobs/claim",
            headers=_auth(_WORKER_TOKEN),
            json={
                "worker_id": "resume-abac-worker-1",
                "kinds": ["campaign"],
                "lease_seconds": 30,
            },
        )
        assert claimed.status_code == 200, claimed.text
        expires_at = datetime.now(UTC) + timedelta(minutes=5)
        created = client.post(
            f"/v1/worker/jobs/{job_id}/checkpoints",
            headers=_auth(_WORKER_TOKEN),
            json={
                "worker_id": "resume-abac-worker-1",
                "lease_token": claimed.json()["lease_token"],
                "state": {"turn": 1, "messages": ["signed continuation state"]},
                "pending_intent": {
                    "call_fingerprint": "a" * 64,
                    "tool_id": "mock.approval-probe",
                    "target": "lab://resume-abac",
                    "risk_tier": 3,
                    "expires_at": expires_at.isoformat(),
                },
            },
        )
        assert created.status_code == 200, created.text
        checkpoint_id = str(created.json()["checkpoint"]["checkpoint_id"])
        approval_id = str(created.json()["approval"]["approval_id"])
        approved = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=_auth(_APPROVER_TOKEN),
            json={"approve": True, "reason": "exact continuation intent approved"},
        )
        assert approved.status_code == 200, approved.text
        with app.state.repository.read_transaction() as session:
            checkpoint = session.get(CheckpointRecord, checkpoint_id)
            approval = session.get(ApprovalRecord, approval_id)
            assert checkpoint is not None and approval is not None
            material: dict[str, Any] = {
                "checkpoint_id": checkpoint.checkpoint_id,
                "run_id": checkpoint.run_id,
                "sequence": checkpoint.sequence,
                "schema_version": checkpoint.schema_version,
                "payload_sha256": checkpoint.payload_sha256,
                "signature": checkpoint.signature,
                "key_id": checkpoint.key_id,
                "approval_id": approval.approval_id,
                "call_fingerprint": approval.call_fingerprint,
                "tool_id": approval.tool_id,
                "target": approval.target,
                "risk_tier": approval.risk_tier,
                "expires_at": approval.expires_at.replace(tzinfo=UTC),
            }
    return _ApprovedCheckpoint(
        database_path=database_path,
        run_id=run_id,
        checkpoint_id=checkpoint_id,
        approval_id=approval_id,
        authority_material=material,
    )


def _resume(
    client: TestClient,
    workflow: _ApprovedCheckpoint,
    *,
    token: str = _OPERATOR_TOKEN,
) -> Response:
    return client.post(
        f"/v1/checkpoints/{workflow.checkpoint_id}/resume",
        headers=_auth(token),
        json={"approval_id": workflow.approval_id},
    )


def test_checkpoint_resume_policy_is_strict_and_exact() -> None:
    digest = "a" * 64
    exact_rule = _policy(digest).checkpoint_resume_rules[0]
    with pytest.raises(ValidationError, match="checkpoint resume rules must be unique"):
        ControlPlaneCheckpointResumeABACPolicy(
            policy_id="checkpoint-resume-policy_0123456789abcdef0123456789abcdef",
            checkpoint_resume_rules=(exact_rule, exact_rule),
        )
    with pytest.raises(ValidationError, match="String should match pattern"):
        CheckpointResumeRule(
            principal_subject=_OPERATOR_SUBJECT,
            action="checkpoint.resume",
            checkpoint_resume_authority_digest="g" * 64,
        )
    raw = _policy(digest).model_dump(mode="json")
    raw["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_checkpoint_resume_abac_policy(json.dumps(raw).encode("utf-8"))

    authorizer = ControlPlaneCheckpointResumeAuthorizer(_policy(digest))
    with pytest.raises(AuthorizationDenied, match="denied the checkpoint resume"):
        authorizer.authorize_checkpoint_resume(
            principal_subject=_OPERATOR_SUBJECT,
            checkpoint_resume_authority_digest="b" * 64,
        )


def test_checkpoint_resume_rules_must_name_authenticated_operators(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="authenticated Operator subjects"):
        _settings(tmp_path / "control-plane.db", _policy("a" * 64, subject="unknown-operator"))


def test_environment_loads_checkpoint_resume_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _policy("a" * 64)
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", _OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_OPERATOR_SUBJECT", _OPERATOR_SUBJECT)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", _APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", _WORKER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_CHECKPOINT_KEY", _CHECKPOINT_KEY.decode())
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_RESUME_ABAC_POLICY",
        policy.model_dump_json(),
    )
    monkeypatch.delenv("PAJIN_CP_ABAC_POLICY", raising=False)
    monkeypatch.delenv("PAJIN_CP_RUN_CANCELLATION_ABAC_POLICY", raising=False)
    monkeypatch.delenv("PAJIN_CP_OIDC_HUMAN_TRUST_POLICY", raising=False)
    monkeypatch.delenv("PAJIN_CP_WORKER_MTLS_TRUST_POLICY", raising=False)

    settings = ControlPlaneSettings.from_env()

    assert settings.checkpoint_resume_abac_policy == policy


def test_exact_checkpoint_resume_authority_can_be_consumed(tmp_path: Path) -> None:
    workflow = _prepare_approved_checkpoint(tmp_path)
    digest = checkpoint_resume_authority_digest(**workflow.authority_material)
    app = create_app(_settings(workflow.database_path, _policy(digest)))
    with TestClient(app) as client:
        resumed = _resume(client, workflow)

    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["approval"]["state"] == ApprovalState.CONSUMED.value
    assert resumed.json()["checkpoint"]["claimed_by"] == _OPERATOR_SUBJECT
    assert resumed.json()["checkpoint"]["continuation_job_id"] == resumed.json()["job"]["job_id"]


def test_unlisted_operator_is_denied_before_and_after_exact_consumption(
    tmp_path: Path,
) -> None:
    workflow = _prepare_approved_checkpoint(tmp_path)
    digest = checkpoint_resume_authority_digest(**workflow.authority_material)
    app = create_app(_settings(workflow.database_path, _policy(digest)))
    with TestClient(app) as client:
        denied = _resume(client, workflow, token=_OTHER_OPERATOR_TOKEN)
        allowed = _resume(client, workflow)
        denied_repeat = _resume(client, workflow, token=_OTHER_OPERATOR_TOKEN)

    assert denied.status_code == 403
    assert denied.json() == {"detail": "ABAC policy denied the checkpoint resume"}
    assert allowed.status_code == 200, allowed.text
    assert denied_repeat.status_code == 403
    assert denied_repeat.json() == {"detail": "ABAC policy denied the checkpoint resume"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("approval_id", "approval_ffffffffffffffffffffffffffffffff"),
        ("target", "lab://other-resume-target"),
        ("payload_sha256", "f" * 64),
        ("key_id", "other-key"),
    ],
    ids=["approval", "target", "signed-payload", "signing-key"],
)
def test_mismatched_resume_authority_denies_without_mutation(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    workflow = _prepare_approved_checkpoint(tmp_path)
    mismatched = {**workflow.authority_material, field: value}
    policy = _policy(checkpoint_resume_authority_digest(**mismatched))
    app = create_app(_settings(workflow.database_path, policy))
    with TestClient(app) as client:
        with app.state.repository.read_transaction() as session:
            events_before = session.scalar(
                select(func.count())
                .select_from(EventRecord)
                .where(EventRecord.run_id == workflow.run_id)
            )
            jobs_before = session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(JobRecord.run_id == workflow.run_id)
            )

        denied = _resume(client, workflow)

        with app.state.repository.read_transaction() as session:
            checkpoint = session.get(CheckpointRecord, workflow.checkpoint_id)
            approval = session.get(ApprovalRecord, workflow.approval_id)
            run = session.get(RunRecord, workflow.run_id)
            checkpoint_state = (
                None
                if checkpoint is None
                else (checkpoint.claimed_at, checkpoint.continuation_job_id)
            )
            approval_state = (
                None
                if approval is None
                else (approval.state, approval.consumed_by, approval.consumed_at)
            )
            run_state = None if run is None else run.state
            events_after = session.scalar(
                select(func.count())
                .select_from(EventRecord)
                .where(EventRecord.run_id == workflow.run_id)
            )
            jobs_after = session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(JobRecord.run_id == workflow.run_id)
            )

    assert denied.status_code == 403
    assert denied.json() == {"detail": "ABAC policy denied the checkpoint resume"}
    assert checkpoint_state == (None, None)
    assert approval_state == (ApprovalState.APPROVED.value, None, None)
    assert run_state == RunState.AWAITING_APPROVAL.value
    assert events_after == events_before
    assert jobs_after == jobs_before
