from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select

from pajin.control_plane.abac import (
    ControlPlaneRunCancellationABACPolicy,
    ControlPlaneRunCancellationAuthorizer,
    RunCancellationRule,
    parse_run_cancellation_abac_policy,
)
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import EventRecord, JobRecord, RunRecord
from pajin.control_plane.errors import AuthorizationDenied
from pajin.control_plane.models import Principal, PrincipalRole, submission_authority_digest

_OPERATOR_TOKEN = "cancel-abac-operator-token-that-is-long-and-distinct"
_OTHER_OPERATOR_TOKEN = "cancel-abac-other-operator-token-that-is-long-and-distinct"
_APPROVER_TOKEN = "cancel-abac-approver-token-that-is-long-and-distinct"
_WORKER_TOKEN = "cancel-abac-worker-token-that-is-long-and-distinct"
_OPERATOR_SUBJECT = "cancel-abac-operator"
_OTHER_OPERATOR_SUBJECT = "cancel-abac-other-operator"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _submission(*, suffix: str = "exact", **updates: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "campaign_name": "cancel-abac-campaign",
        "input": {"objective": "cancel only the deployment-pinned submission"},
        "idempotency_key": f"cancel-abac-{suffix}",
        "max_attempts": 3,
        "job_kind": "campaign",
    }
    body.update(updates)
    return body


def _submission_digest(body: dict[str, Any]) -> str:
    return submission_authority_digest(
        actor=_OPERATOR_SUBJECT,
        campaign_name=str(body["campaign_name"]),
        input_value=body["input"],
        idempotency_key=str(body["idempotency_key"]),
        job_kind=str(body["job_kind"]),
        max_attempts=int(body["max_attempts"]),
    )


def _policy(
    digest: str,
    *,
    subject: str = _OPERATOR_SUBJECT,
) -> ControlPlaneRunCancellationABACPolicy:
    return ControlPlaneRunCancellationABACPolicy(
        policy_id="run-cancel-policy_0123456789abcdef0123456789abcdef",
        run_cancellation_rules=(
            RunCancellationRule(
                principal_subject=subject,
                action="run.cancel",
                submission_authority_digest=digest,
            ),
        ),
    )


def _settings(
    tmp_path: Path,
    policy: ControlPlaneRunCancellationABACPolicy,
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
                subject="cancel-abac-approver",
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            ),
            _WORKER_TOKEN: Principal(
                subject="cancel-abac-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"cancel-abac-checkpoint-key-that-is-long-enough"},
        run_cancellation_abac_policy=policy,
    )


def _submit(client: TestClient, body: dict[str, Any]) -> tuple[str, str]:
    response = client.post("/v1/runs", headers=_auth(_OPERATOR_TOKEN), json=body)
    assert response.status_code == 200, response.text
    return str(response.json()["run"]["run_id"]), str(response.json()["job"]["job_id"])


def test_run_cancellation_policy_is_strict_and_exact() -> None:
    body = _submission()
    exact_rule = _policy(_submission_digest(body)).run_cancellation_rules[0]
    with pytest.raises(ValidationError, match="Run cancellation rules must be unique"):
        ControlPlaneRunCancellationABACPolicy(
            policy_id="run-cancel-policy_0123456789abcdef0123456789abcdef",
            run_cancellation_rules=(exact_rule, exact_rule),
        )
    with pytest.raises(ValidationError, match="String should match pattern"):
        RunCancellationRule(
            principal_subject=_OPERATOR_SUBJECT,
            action="run.cancel",
            submission_authority_digest="g" * 64,
        )
    raw = _policy(_submission_digest(body)).model_dump(mode="json")
    raw["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_run_cancellation_abac_policy(json.dumps(raw).encode("utf-8"))

    authorizer = ControlPlaneRunCancellationAuthorizer(_policy(_submission_digest(body)))
    for invalid_digest in (None, "not-a-valid-submission-authority-digest"):
        with pytest.raises(AuthorizationDenied, match="denied the Run cancellation"):
            authorizer.authorize_run_cancellation(
                principal_subject=_OPERATOR_SUBJECT,
                submission_authority_digest=invalid_digest,
            )


def test_run_cancellation_rules_must_name_authenticated_operators(tmp_path: Path) -> None:
    body = _submission()
    with pytest.raises(ValueError, match="authenticated Operator subjects"):
        _settings(tmp_path, _policy(_submission_digest(body), subject="unknown-operator"))


def test_environment_loads_run_cancellation_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = _submission()
    policy = _policy(_submission_digest(body))
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", _OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_OPERATOR_SUBJECT", _OPERATOR_SUBJECT)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", _APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", _WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "cancel-abac-checkpoint-key-that-is-long-enough",
    )
    monkeypatch.setenv(
        "PAJIN_CP_RUN_CANCELLATION_ABAC_POLICY",
        policy.model_dump_json(),
    )
    monkeypatch.delenv("PAJIN_CP_ABAC_POLICY", raising=False)
    monkeypatch.delenv("PAJIN_CP_OIDC_HUMAN_TRUST_POLICY", raising=False)
    monkeypatch.delenv("PAJIN_CP_WORKER_MTLS_TRUST_POLICY", raising=False)

    settings = ControlPlaneSettings.from_env()

    assert settings.run_cancellation_abac_policy == policy


def test_exact_submission_authority_can_be_cancelled(tmp_path: Path) -> None:
    body = _submission()
    app = create_app(_settings(tmp_path, _policy(_submission_digest(body))))
    with TestClient(app) as client:
        run_id, job_id = _submit(client, body)
        response = client.post(
            f"/v1/runs/{run_id}/cancel",
            headers=_auth(_OPERATOR_TOKEN),
            json={"reason": "the exact deployment-pinned submission must stop"},
        )

    assert response.status_code == 200, response.text
    assert response.json()["applied"] is True
    assert response.json()["run"]["state"] == "cancelled"
    assert response.json()["cancelled_job_ids"] == [job_id]


def test_idempotent_cancellation_still_requires_exact_operator(tmp_path: Path) -> None:
    body = _submission()
    app = create_app(_settings(tmp_path, _policy(_submission_digest(body))))
    with TestClient(app) as client:
        run_id, _job_id = _submit(client, body)
        first = client.post(
            f"/v1/runs/{run_id}/cancel",
            headers=_auth(_OPERATOR_TOKEN),
            json={"reason": "apply the exact cancellation"},
        )
        denied_repeat = client.post(
            f"/v1/runs/{run_id}/cancel",
            headers=_auth(_OTHER_OPERATOR_TOKEN),
            json={"reason": "idempotency must not bypass ABAC"},
        )
        allowed_repeat = client.post(
            f"/v1/runs/{run_id}/cancel",
            headers=_auth(_OPERATOR_TOKEN),
            json={"reason": "exact idempotent retry"},
        )

    assert first.status_code == 200
    assert denied_repeat.status_code == 403
    assert denied_repeat.json() == {"detail": "ABAC policy denied the Run cancellation"}
    assert allowed_repeat.status_code == 200
    assert allowed_repeat.json()["applied"] is False


@pytest.mark.parametrize(
    "updates",
    [
        {"campaign_name": "cancel-abac-other-campaign"},
        {"input": {"objective": "substituted input"}},
        {"idempotency_key": "cancel-abac-other-idempotency"},
        {"job_kind": "tool-loop"},
        {"max_attempts": 4},
    ],
    ids=["campaign", "input", "idempotency", "job-kind", "retry-limit"],
)
def test_mismatched_submission_authority_denies_without_mutation(
    tmp_path: Path,
    updates: dict[str, Any],
) -> None:
    allowed = _submission()
    submitted = _submission(suffix="mismatch", **updates)
    app = create_app(_settings(tmp_path, _policy(_submission_digest(allowed))))
    with TestClient(app) as client:
        run_id, job_id = _submit(client, submitted)
        with app.state.repository.read_transaction() as session:
            events_before = session.scalar(
                select(func.count()).select_from(EventRecord).where(EventRecord.run_id == run_id)
            )

        response = client.post(
            f"/v1/runs/{run_id}/cancel",
            headers=_auth(_OPERATOR_TOKEN),
            json={"reason": "request data cannot expand cancellation authority"},
        )

        with app.state.repository.read_transaction() as session:
            run_state = session.scalar(select(RunRecord.state).where(RunRecord.run_id == run_id))
            job_state = session.scalar(select(JobRecord.state).where(JobRecord.job_id == job_id))
            events_after = session.scalar(
                select(func.count()).select_from(EventRecord).where(EventRecord.run_id == run_id)
            )

    assert response.status_code == 403
    assert response.json() == {"detail": "ABAC policy denied the Run cancellation"}
    assert run_state == "queued"
    assert job_state == "queued"
    assert events_after == events_before


def test_nonmatching_operator_denies_without_mutation(tmp_path: Path) -> None:
    body = _submission()
    app = create_app(_settings(tmp_path, _policy(_submission_digest(body))))
    with TestClient(app) as client:
        run_id, _job_id = _submit(client, body)
        response = client.post(
            f"/v1/runs/{run_id}/cancel",
            headers=_auth(_OTHER_OPERATOR_TOKEN),
            json={"reason": "a role alone must not authorize cancellation"},
        )
        run = client.get(f"/v1/runs/{run_id}", headers=_auth(_OPERATOR_TOKEN))

    assert response.status_code == 403
    assert response.json() == {"detail": "ABAC policy denied the Run cancellation"}
    assert run.json()["state"] == "queued"
