from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select

from pajin.control_plane.abac import (
    ApprovalDecisionRule,
    ControlPlaneABACPolicy,
    parse_control_plane_abac_policy,
)
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import ApprovalRecord, EventRecord
from pajin.control_plane.models import ApprovalState, Principal, PrincipalRole
from pajin.domain.models import ToolRiskTier

_OPERATOR_TOKEN = "abac-operator-token-that-is-long-and-distinct"
_APPROVER_TOKEN = "abac-approver-token-that-is-long-and-distinct"
_WORKER_TOKEN = "abac-worker-token-that-is-long-and-distinct"
_APPROVER_SUBJECT = "abac-approver"
_TOOL_ID = "mock.approval-probe"
_TARGET = "lab://approval-check"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _policy(
    *,
    subject: str = _APPROVER_SUBJECT,
    tool_id: str = _TOOL_ID,
    target: str = _TARGET,
    risk_tier: ToolRiskTier = ToolRiskTier.T3,
) -> ControlPlaneABACPolicy:
    return ControlPlaneABACPolicy(
        policy_id="abac-policy_0123456789abcdef0123456789abcdef",
        approval_decision_rules=(
            ApprovalDecisionRule(
                principal_subject=subject,
                action="approval.decide",
                tool_id=tool_id,
                target=target,
                risk_tier=risk_tier,
            ),
        ),
    )


def _settings(tmp_path: Path, policy: ControlPlaneABACPolicy) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{(tmp_path / 'control-plane.db').as_posix()}",
        credentials={
            _OPERATOR_TOKEN: Principal(
                subject="abac-operator",
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            _APPROVER_TOKEN: Principal(
                subject=_APPROVER_SUBJECT,
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            ),
            _WORKER_TOKEN: Principal(
                subject="abac-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"abac-checkpoint-signing-key-that-is-long-enough"},
        abac_policy=policy,
    )


def _pending_approval(
    client: TestClient,
    *,
    suffix: str,
    tool_id: str = _TOOL_ID,
    target: str = _TARGET,
    risk_tier: ToolRiskTier = ToolRiskTier.T3,
) -> tuple[str, str]:
    submitted = client.post(
        "/v1/runs",
        headers=_auth(_OPERATOR_TOKEN),
        json={
            "campaign_name": "abac-control-plane",
            "idempotency_key": f"abac-{suffix}",
        },
    )
    assert submitted.status_code == 200, submitted.text
    run_id = str(submitted.json()["run"]["run_id"])
    job_id = str(submitted.json()["job"]["job_id"])
    claimed = client.post(
        "/v1/worker/jobs/claim",
        headers=_auth(_WORKER_TOKEN),
        json={"worker_id": "abac-worker", "kinds": ["campaign"], "lease_seconds": 30},
    )
    assert claimed.status_code == 200, claimed.text
    checkpoint = client.post(
        f"/v1/worker/jobs/{job_id}/checkpoints",
        headers=_auth(_WORKER_TOKEN),
        json={
            "worker_id": "abac-worker",
            "lease_token": claimed.json()["lease_token"],
            "state": {"turn": 1},
            "pending_intent": {
                "call_fingerprint": "a" * 64,
                "tool_id": tool_id,
                "target": target,
                "risk_tier": int(risk_tier),
                "expires_at": "2099-01-01T00:00:00Z",
            },
        },
    )
    assert checkpoint.status_code == 200, checkpoint.text
    return run_id, str(checkpoint.json()["approval"]["approval_id"])


def test_abac_policy_is_strict_bounded_and_high_risk_only() -> None:
    exact_rule = ApprovalDecisionRule(
        principal_subject=_APPROVER_SUBJECT,
        action="approval.decide",
        tool_id=_TOOL_ID,
        target=_TARGET,
        risk_tier=ToolRiskTier.T3,
    )
    with pytest.raises(ValidationError, match="decision rules must be unique"):
        ControlPlaneABACPolicy(
            policy_id="abac-policy_0123456789abcdef0123456789abcdef",
            approval_decision_rules=(exact_rule, exact_rule),
        )
    with pytest.raises(ValidationError, match="only T3 or T4"):
        _policy(risk_tier=ToolRiskTier.T2)
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_control_plane_abac_policy(
            b'{"api_version":"pajin.control-plane.abac-policy/v1",'
            b'"policy_id":"abac-policy_0123456789abcdef0123456789abcdef",'
            b'"approval_decision_rules":[{"principal_subject":"abac-approver",'
            b'"action":"approval.decide","tool_id":"mock.approval-probe",'
            b'"target":"lab://approval-check","risk_tier":3,"unexpected":true}]}'
        )


def test_abac_policy_rules_must_name_authenticated_approvers(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="authenticated Approver subjects"):
        _settings(tmp_path, _policy(subject="unknown-approver"))


def test_environment_loads_the_abac_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", _OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", _APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_SUBJECT", _APPROVER_SUBJECT)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", _WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "abac-checkpoint-signing-key-that-is-long-enough",
    )
    monkeypatch.setenv("PAJIN_CP_ABAC_POLICY", _policy().model_dump_json())
    monkeypatch.delenv("PAJIN_CP_OIDC_HUMAN_TRUST_POLICY", raising=False)
    monkeypatch.delenv("PAJIN_CP_WORKER_MTLS_TRUST_POLICY", raising=False)

    settings = ControlPlaneSettings.from_env()

    assert settings.abac_policy == _policy()


def test_exact_signed_approval_attributes_are_authorized(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path, _policy()))
    with TestClient(app) as client:
        _run_id, approval_id = _pending_approval(client, suffix="allowed")
        decision = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=_auth(_APPROVER_TOKEN),
            json={"approve": True, "reason": "exact signed attributes are permitted"},
        )

    assert decision.status_code == 200, decision.text
    assert decision.json()["state"] == "approved"
    assert decision.json()["decided_by"] == _APPROVER_SUBJECT


@pytest.mark.parametrize(
    ("tool_id", "target", "risk_tier"),
    [
        ("mock.other-tool", _TARGET, ToolRiskTier.T3),
        (_TOOL_ID, "lab://other-target", ToolRiskTier.T3),
        (_TOOL_ID, _TARGET, ToolRiskTier.T4),
    ],
    ids=["tool", "target", "risk-tier"],
)
def test_mismatched_signed_attribute_denies_without_mutation(
    tmp_path: Path,
    tool_id: str,
    target: str,
    risk_tier: ToolRiskTier,
) -> None:
    app = create_app(_settings(tmp_path, _policy()))
    with TestClient(app) as client:
        run_id, approval_id = _pending_approval(
            client,
            suffix=risk_tier.name.lower() + tool_id[-4:] + target[-4:],
            tool_id=tool_id,
            target=target,
            risk_tier=risk_tier,
        )
        with app.state.repository.read_transaction() as session:
            events_before = session.scalar(
                select(func.count()).select_from(EventRecord).where(EventRecord.run_id == run_id)
            )

        decision = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=_auth(_APPROVER_TOKEN),
            json={"approve": True, "reason": "caller data cannot expand the ABAC rule"},
        )

        with app.state.repository.read_transaction() as session:
            approval = session.get(ApprovalRecord, approval_id)
            approval_state = approval.state if approval is not None else None
            approval_decided_by = approval.decided_by if approval is not None else None
            events_after = session.scalar(
                select(func.count()).select_from(EventRecord).where(EventRecord.run_id == run_id)
            )

    assert decision.status_code == 403
    assert decision.json() == {"detail": "ABAC policy denied the approval decision"}
    assert approval is not None
    assert approval_state == ApprovalState.PENDING.value
    assert approval_decided_by is None
    assert events_after == events_before
