from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import update

from pajin.control_plane.abac import (
    ControlPlaneMaintenanceABACPolicy,
    ControlPlaneMaintenanceAuthorizer,
    MaintenanceRequeueExpiredRule,
    parse_maintenance_abac_policy,
)
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import JobRecord
from pajin.control_plane.errors import AuthorizationDenied
from pajin.control_plane.models import Principal, PrincipalRole

_OPERATOR_TOKEN = "maintenance-abac-operator-token-that-is-long-and-distinct"
_OTHER_OPERATOR_TOKEN = "maintenance-abac-other-operator-token-that-is-long-and-distinct"
_APPROVER_TOKEN = "maintenance-abac-approver-token-that-is-long-and-distinct"
_WORKER_TOKEN = "maintenance-abac-worker-token-that-is-long-and-distinct"
_OPERATOR_SUBJECT = "maintenance-abac-operator"
_OTHER_OPERATOR_SUBJECT = "maintenance-abac-other-operator"
_WORKER_SUBJECT = "maintenance-abac-worker"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _policy(*, subject: str = _OPERATOR_SUBJECT) -> ControlPlaneMaintenanceABACPolicy:
    return ControlPlaneMaintenanceABACPolicy(
        policy_id="maintenance-policy_0123456789abcdef0123456789abcdef",
        maintenance_requeue_expired_rules=(
            MaintenanceRequeueExpiredRule(
                principal_subject=subject,
                action="maintenance.requeue-expired",
            ),
        ),
    )


def _settings(
    tmp_path: Path,
    policy: ControlPlaneMaintenanceABACPolicy | None,
) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{(tmp_path / 'control-plane.db').as_posix()}",
        credentials={
            _OPERATOR_TOKEN: Principal(
                subject=_OPERATOR_SUBJECT,
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            _OTHER_OPERATOR_TOKEN: Principal(
                subject=_OTHER_OPERATOR_SUBJECT,
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            _APPROVER_TOKEN: Principal(
                subject="maintenance-abac-approver",
                roles=frozenset({PrincipalRole.APPROVER}),
            ),
            _WORKER_TOKEN: Principal(
                subject=_WORKER_SUBJECT,
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"maintenance-abac-checkpoint-key-that-is-long-enough"},
        maintenance_abac_policy=policy,
    )


class _StubLifecycle:
    def __init__(self) -> None:
        self.actors: list[str] = []

    def requeue_expired(self, *, actor: str) -> int:
        self.actors.append(actor)
        return 7


def test_maintenance_policy_is_strict_and_exact() -> None:
    policy = _policy()
    exact_rule = policy.maintenance_requeue_expired_rules[0]
    with pytest.raises(ValidationError, match="requeue-expired rules must be unique"):
        ControlPlaneMaintenanceABACPolicy(
            policy_id="maintenance-policy_0123456789abcdef0123456789abcdef",
            maintenance_requeue_expired_rules=(exact_rule, exact_rule),
        )
    raw = policy.model_dump(mode="json")
    raw["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_maintenance_abac_policy(json.dumps(raw).encode("utf-8"))

    authorizer = ControlPlaneMaintenanceAuthorizer(policy)
    with pytest.raises(AuthorizationDenied, match="maintenance requeue-expired"):
        authorizer.authorize_requeue_expired(principal_subject=_OTHER_OPERATOR_SUBJECT)


def test_maintenance_rules_must_name_authenticated_operators(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="authenticated Operator subjects"):
        _settings(tmp_path, _policy(subject="unknown-operator"))


def test_environment_loads_maintenance_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _policy()
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", _OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_OPERATOR_SUBJECT", _OPERATOR_SUBJECT)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", _APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", _WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "maintenance-abac-checkpoint-key-that-is-long-enough",
    )
    monkeypatch.setenv("PAJIN_CP_MAINTENANCE_ABAC_POLICY", policy.model_dump_json())
    for name in (
        "PAJIN_CP_ABAC_POLICY",
        "PAJIN_CP_RUN_SUBMISSION_ABAC_POLICY",
        "PAJIN_CP_RUN_CANCELLATION_ABAC_POLICY",
        "PAJIN_CP_CHECKPOINT_RESUME_ABAC_POLICY",
        "PAJIN_CP_REPLAY_SOURCE_ARTIFACT_ABAC_POLICY",
        "PAJIN_CP_REPLAY_BATCH_ADMISSION_ABAC_POLICY",
        "PAJIN_CP_OIDC_HUMAN_TRUST_POLICY",
        "PAJIN_CP_WORKER_MTLS_TRUST_POLICY",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = ControlPlaneSettings.from_env()

    assert settings.maintenance_abac_policy == policy


def test_exact_operator_maintenance_action_is_authorized_before_delegate(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path, _policy()))
    stub = _StubLifecycle()
    with TestClient(app) as client:
        app.state.control_plane._lifecycle = stub
        first = client.post(
            "/v1/maintenance/requeue-expired",
            headers=_auth(_OPERATOR_TOKEN),
        )
        repeat = client.post(
            "/v1/maintenance/requeue-expired",
            headers=_auth(_OPERATOR_TOKEN),
        )
        denied = client.post(
            "/v1/maintenance/requeue-expired",
            headers=_auth(_OTHER_OPERATOR_TOKEN),
        )

    assert first.status_code == 200, first.text
    assert first.json() == {"requeuedOrDeadLettered": 7}
    assert repeat.status_code == 200, repeat.text
    assert denied.status_code == 403
    assert denied.json() == {"detail": "ABAC policy denied the maintenance requeue-expired action"}
    assert stub.actors == [_OPERATOR_SUBJECT, _OPERATOR_SUBJECT]


@pytest.mark.parametrize("token", [_APPROVER_TOKEN, _WORKER_TOKEN])
def test_non_operator_cannot_invoke_explicit_maintenance_route(
    tmp_path: Path,
    token: str,
) -> None:
    app = create_app(_settings(tmp_path, _policy()))
    stub = _StubLifecycle()
    with TestClient(app) as client:
        app.state.control_plane._lifecycle = stub
        response = client.post(
            "/v1/maintenance/requeue-expired",
            headers=_auth(token),
        )

    assert response.status_code == 403
    assert stub.actors == []


def test_policy_omission_preserves_operator_rbac_maintenance(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path, None))
    stub = _StubLifecycle()
    with TestClient(app) as client:
        app.state.control_plane._lifecycle = stub
        response = client.post(
            "/v1/maintenance/requeue-expired",
            headers=_auth(_OTHER_OPERATOR_TOKEN),
        )

    assert response.status_code == 200, response.text
    assert response.json() == {"requeuedOrDeadLettered": 7}
    assert stub.actors == [_OTHER_OPERATOR_SUBJECT]


def test_worker_claim_keeps_internal_opportunistic_lease_sweep(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path, _policy()))
    with TestClient(app) as client:
        submitted = client.post(
            "/v1/runs",
            headers=_auth(_OPERATOR_TOKEN),
            json={
                "campaign_name": "maintenance-abac-internal-sweep",
                "input": {"objective": "preserve server-owned lease cleanup"},
                "idempotency_key": "maintenance-abac-internal-sweep",
                "max_attempts": 3,
            },
        )
        assert submitted.status_code == 200, submitted.text
        job_id = submitted.json()["job"]["job_id"]
        first = client.post(
            "/v1/worker/jobs/claim",
            headers=_auth(_WORKER_TOKEN),
            json={"worker_id": "worker-1", "kinds": ["campaign"], "lease_seconds": 30},
        )
        assert first.status_code == 200, first.text

        with app.state.repository.transaction() as session:
            session.execute(
                update(JobRecord)
                .where(JobRecord.job_id == job_id)
                .values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )

        second = client.post(
            "/v1/worker/jobs/claim",
            headers=_auth(_WORKER_TOKEN),
            json={"worker_id": "worker-2", "kinds": ["campaign"], "lease_seconds": 30},
        )

    assert second.status_code == 200, second.text
    assert second.json()["job"]["job_id"] == job_id
    assert second.json()["job"]["attempts"] == 2
