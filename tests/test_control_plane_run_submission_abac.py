from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from pydantic import ValidationError
from sqlalchemy import func, select

from pajin.control_plane.abac import (
    ControlPlaneRunSubmissionABACPolicy,
    ControlPlaneRunSubmissionAuthorizer,
    RunSubmissionRule,
    parse_run_submission_abac_policy,
)
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import EventRecord, JobRecord, RunRecord
from pajin.control_plane.errors import AuthorizationDenied
from pajin.control_plane.models import Principal, PrincipalRole, submission_authority_digest

_OPERATOR_TOKEN = "submit-abac-operator-token-that-is-long-and-distinct"
_OTHER_OPERATOR_TOKEN = "submit-abac-other-operator-token-that-is-long-and-distinct"
_APPROVER_TOKEN = "submit-abac-approver-token-that-is-long-and-distinct"
_WORKER_TOKEN = "submit-abac-worker-token-that-is-long-and-distinct"
_OPERATOR_SUBJECT = "submit-abac-operator"
_OTHER_OPERATOR_SUBJECT = "submit-abac-other-operator"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _submission(*, suffix: str = "exact", **updates: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "campaign_name": "submit-abac-campaign",
        "input": {"objective": "create only the deployment-pinned Run"},
        "idempotency_key": f"submit-abac-{suffix}",
        "max_attempts": 3,
        "job_kind": "campaign",
    }
    body.update(updates)
    return body


def _submission_digest(
    body: dict[str, Any],
    *,
    actor: str = _OPERATOR_SUBJECT,
) -> str:
    return submission_authority_digest(
        actor=actor,
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
) -> ControlPlaneRunSubmissionABACPolicy:
    return ControlPlaneRunSubmissionABACPolicy(
        policy_id="run-submit-policy_0123456789abcdef0123456789abcdef",
        run_submission_rules=(
            RunSubmissionRule(
                principal_subject=subject,
                action="run.submit",
                submission_authority_digest=digest,
            ),
        ),
    )


def _settings(
    tmp_path: Path,
    policy: ControlPlaneRunSubmissionABACPolicy,
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
                subject="submit-abac-approver",
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            ),
            _WORKER_TOKEN: Principal(
                subject="submit-abac-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"submit-abac-checkpoint-key-that-is-long-enough"},
        run_submission_abac_policy=policy,
    )


def _submit(
    client: TestClient,
    body: dict[str, Any],
    *,
    token: str = _OPERATOR_TOKEN,
) -> Response:
    return client.post("/v1/runs", headers=_auth(token), json=body)


def _durable_counts(app: Any) -> tuple[int, int, int]:
    with app.state.repository.read_transaction() as session:
        runs = session.scalar(select(func.count()).select_from(RunRecord))
        jobs = session.scalar(select(func.count()).select_from(JobRecord))
        events = session.scalar(select(func.count()).select_from(EventRecord))
    assert runs is not None and jobs is not None and events is not None
    return runs, jobs, events


def test_run_submission_policy_is_strict_and_exact() -> None:
    digest = "a" * 64
    exact_rule = _policy(digest).run_submission_rules[0]
    with pytest.raises(ValidationError, match="Run submission rules must be unique"):
        ControlPlaneRunSubmissionABACPolicy(
            policy_id="run-submit-policy_0123456789abcdef0123456789abcdef",
            run_submission_rules=(exact_rule, exact_rule),
        )
    with pytest.raises(ValidationError, match="String should match pattern"):
        RunSubmissionRule(
            principal_subject=_OPERATOR_SUBJECT,
            action="run.submit",
            submission_authority_digest="g" * 64,
        )
    raw = _policy(digest).model_dump(mode="json")
    raw["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_run_submission_abac_policy(json.dumps(raw).encode("utf-8"))

    authorizer = ControlPlaneRunSubmissionAuthorizer(_policy(digest))
    with pytest.raises(AuthorizationDenied, match="denied the Run submission"):
        authorizer.authorize_run_submission(
            principal_subject=_OPERATOR_SUBJECT,
            submission_authority_digest="b" * 64,
        )


def test_run_submission_rules_must_name_authenticated_operators(tmp_path: Path) -> None:
    body = _submission()
    with pytest.raises(ValueError, match="authenticated Operator subjects"):
        _settings(tmp_path, _policy(_submission_digest(body), subject="unknown-operator"))


def test_environment_loads_run_submission_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    body = _submission()
    policy = _policy(_submission_digest(body))
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", _OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_OPERATOR_SUBJECT", _OPERATOR_SUBJECT)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", _APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", _WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "submit-abac-checkpoint-key-that-is-long-enough",
    )
    monkeypatch.setenv("PAJIN_CP_RUN_SUBMISSION_ABAC_POLICY", policy.model_dump_json())
    monkeypatch.delenv("PAJIN_CP_ABAC_POLICY", raising=False)
    monkeypatch.delenv("PAJIN_CP_RUN_CANCELLATION_ABAC_POLICY", raising=False)
    monkeypatch.delenv("PAJIN_CP_CHECKPOINT_RESUME_ABAC_POLICY", raising=False)
    monkeypatch.delenv("PAJIN_CP_OIDC_HUMAN_TRUST_POLICY", raising=False)
    monkeypatch.delenv("PAJIN_CP_WORKER_MTLS_TRUST_POLICY", raising=False)

    settings = ControlPlaneSettings.from_env()

    assert settings.run_submission_abac_policy == policy


def test_exact_submission_authority_can_create_run(tmp_path: Path) -> None:
    body = _submission()
    app = create_app(_settings(tmp_path, _policy(_submission_digest(body))))
    with TestClient(app) as client:
        response = _submit(client, body)

    assert response.status_code == 200, response.text
    assert response.json()["created"] is True
    assert response.json()["run"]["state"] == "queued"
    assert response.json()["job"]["state"] == "queued"


def test_idempotent_submission_still_requires_exact_operator(tmp_path: Path) -> None:
    body = _submission()
    app = create_app(_settings(tmp_path, _policy(_submission_digest(body))))
    with TestClient(app) as client:
        first = _submit(client, body)
        denied_repeat = _submit(client, body, token=_OTHER_OPERATOR_TOKEN)
        allowed_repeat = _submit(client, body)

    assert first.status_code == 200
    assert denied_repeat.status_code == 403
    assert denied_repeat.json() == {"detail": "ABAC policy denied the Run submission"}
    assert allowed_repeat.status_code == 200
    assert allowed_repeat.json()["created"] is False
    assert allowed_repeat.json()["run"]["run_id"] == first.json()["run"]["run_id"]


@pytest.mark.parametrize(
    "updates",
    [
        {"campaign_name": "submit-abac-other-campaign"},
        {"input": {"objective": "substituted input"}},
        {"idempotency_key": "submit-abac-other-idempotency"},
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
    attempted = _submission(suffix="mismatch", **updates)
    app = create_app(_settings(tmp_path, _policy(_submission_digest(allowed))))
    with TestClient(app) as client:
        before = _durable_counts(app)
        response = _submit(client, attempted)
        after = _durable_counts(app)

    assert response.status_code == 403
    assert response.json() == {"detail": "ABAC policy denied the Run submission"}
    assert after == before == (0, 0, 0)


def test_unlisted_operator_denies_without_mutation(tmp_path: Path) -> None:
    body = _submission()
    app = create_app(_settings(tmp_path, _policy(_submission_digest(body))))
    with TestClient(app) as client:
        response = _submit(client, body, token=_OTHER_OPERATOR_TOKEN)
        counts = _durable_counts(app)

    assert response.status_code == 403
    assert response.json() == {"detail": "ABAC policy denied the Run submission"}
    assert counts == (0, 0, 0)
