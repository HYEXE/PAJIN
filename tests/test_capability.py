from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.domain.manifest import load_manifest
from pajin.domain.models import Authorization, CapabilityGrant, ToolRiskTier
from pajin.policy.capability import CapabilityError, CapabilityLedger


def test_child_capability_must_attenuate_parent() -> None:
    expiry = datetime.now(UTC) + timedelta(hours=1)
    parent = CapabilityGrant(
        subject="agent:parent",
        campaign="test-campaign",
        tools={"mock.agent-probe", "report.read"},
        targets={"https://example.invalid/api/chat"},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=20,
        expires_at=expiry,
        delegable=True,
    )
    child = CapabilityGrant(
        parent_grant_id=parent.grant_id,
        subject="agent:child",
        campaign="test-campaign",
        tools={"mock.agent-probe"},
        targets={"https://example.invalid/api/chat"},
        max_risk_tier=ToolRiskTier.T1,
        max_calls=5,
        expires_at=expiry - timedelta(minutes=30),
        delegable=False,
        depth=1,
    )

    assert child.attenuates(parent)
    assert not child.model_copy(update={"max_calls": 21}).attenuates(parent)
    assert not child.model_copy(update={"tools": {"shell.execute"}}).attenuates(parent)
    assert not child.model_copy(
        update={"issued_at": parent.issued_at - timedelta(seconds=1)}
    ).attenuates(parent)


def test_non_delegable_parent_cannot_issue_child() -> None:
    expiry = datetime.now(UTC) + timedelta(hours=1)
    parent = CapabilityGrant(
        subject="agent:parent",
        campaign="test-campaign",
        tools={"mock.agent-probe"},
        targets={"https://example.invalid/api/chat"},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=20,
        expires_at=expiry,
        delegable=False,
    )
    child = parent.model_copy(update={"subject": "agent:child", "max_calls": 1, "delegable": False})

    assert not child.attenuates(parent)


@pytest.mark.parametrize("field", ["approved_at", "expires_at"])
def test_authorization_rejects_naive_authority_timestamps(field: str) -> None:
    payload: dict[str, object] = {
        "approved_at": datetime(2026, 7, 19),
        "expires_at": datetime(2026, 7, 20, tzinfo=UTC),
        "approved_by": "owner",
        "evidence": "approval-record",
    }
    if field == "expires_at":
        payload["approved_at"] = datetime(2026, 7, 19, tzinfo=UTC)
        payload["expires_at"] = datetime(2026, 7, 20)

    with pytest.raises(ValidationError, match="explicit UTC offset"):
        Authorization.model_validate(payload)


@pytest.mark.parametrize("field", ["issued_at", "expires_at"])
def test_capability_rejects_naive_authority_timestamps(field: str) -> None:
    payload: dict[str, object] = {
        "subject": "agent:test",
        "campaign": "test-campaign",
        "max_risk_tier": ToolRiskTier.T1,
        "max_calls": 1,
        "issued_at": datetime(2026, 7, 19, tzinfo=UTC),
        "expires_at": datetime(2026, 7, 20, tzinfo=UTC),
    }
    payload[field] = datetime(2026, 7, 19)

    with pytest.raises(ValidationError, match="explicit UTC offset"):
        CapabilityGrant.model_validate(payload)


def test_authority_timestamps_normalize_to_utc_and_reject_naive_evaluation() -> None:
    korea = timezone(timedelta(hours=9))
    authorization = Authorization(
        approvedBy="owner",
        approvedAt=datetime(2026, 7, 19, 9, tzinfo=korea),
        expiresAt=datetime(2026, 7, 20, 9, tzinfo=korea),
        evidence="approval-record",
    )

    assert authorization.approved_at == datetime(2026, 7, 19, tzinfo=UTC)
    assert authorization.expires_at == datetime(2026, 7, 20, tzinfo=UTC)
    with pytest.raises(ValueError, match="evaluation timestamp"):
        authorization.is_active(datetime(2026, 7, 19, 12))


def test_attenuation_rejects_bypassed_naive_timestamp_with_typed_error() -> None:
    expiry = datetime.now(UTC) + timedelta(hours=1)
    parent = CapabilityGrant(
        subject="agent:parent",
        campaign="test-campaign",
        max_risk_tier=ToolRiskTier.T1,
        max_calls=1,
        expires_at=expiry,
        delegable=True,
    )
    child = CapabilityGrant(
        parent_grant_id=parent.grant_id,
        subject="agent:child",
        campaign=parent.campaign,
        max_risk_tier=ToolRiskTier.T1,
        max_calls=1,
        issued_at=parent.issued_at,
        expires_at=expiry,
        depth=1,
    ).model_copy(update={"issued_at": datetime(2026, 7, 19)})

    with pytest.raises(ValueError, match="explicit UTC offset"):
        child.attenuates(parent)


def test_sibling_grants_cannot_amplify_ancestor_call_budget() -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    ledger = CapabilityLedger(max_depth=1)
    target = campaign.spec.targets[0].endpoint
    root = ledger.issue_root(
        campaign,
        subject="agent:supervisor",
        tools={"mock.agent-probe"},
        targets={target},
    )
    first = ledger.delegate(
        root.grant_id,
        subject="agent:specialist:first",
        tools={"mock.agent-probe"},
        targets={target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=3,
    )
    second = ledger.delegate(
        root.grant_id,
        subject="agent:specialist:second",
        tools={"mock.agent-probe"},
        targets={target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=3,
    )

    for _ in range(3):
        ledger.consume(first.grant_id)

    assert ledger.record(root.grant_id).remaining_calls == 0
    assert not ledger.can_consume(second.grant_id)


def test_capability_revocation_is_idempotent_and_preserves_first_reason() -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    ledger = CapabilityLedger(max_depth=1)
    target = campaign.spec.targets[0].endpoint
    root = ledger.issue_root(
        campaign,
        subject="agent:supervisor",
        tools={"mock.agent-probe"},
        targets={target},
    )
    child = ledger.delegate(
        root.grant_id,
        subject="agent:specialist",
        tools={"mock.agent-probe"},
        targets={target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
    )

    assert ledger.revoke(child.grant_id, "specialist phase completed") == [child.grant_id]
    assert ledger.revoke(root.grant_id, "campaign completed", cascade=True) == [root.grant_id]
    assert ledger.revoke(root.grant_id, "later duplicate", cascade=True) == []
    assert ledger.record(root.grant_id).revoke_reason == "campaign completed"
    assert ledger.record(child.grant_id).revoke_reason == "specialist phase completed"


def test_issued_grant_mutation_cannot_change_ledger_authority() -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    ledger = CapabilityLedger(max_depth=1)
    target = campaign.spec.targets[0].endpoint
    root = ledger.issue_root(
        campaign,
        subject="agent:supervisor",
        tools={"mock.agent-probe"},
        targets={target},
    )
    original_max_calls = root.max_calls

    root.tools.add("shell.execute")
    root.targets.add("https://unapproved.invalid")
    root.max_calls = original_max_calls + 100

    authoritative = ledger.record(root.grant_id)
    assert authoritative.grant.tools == {"mock.agent-probe"}
    assert authoritative.grant.targets == {target}
    assert authoritative.grant.max_calls == original_max_calls


def test_record_mutation_cannot_change_live_ledger_state() -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    ledger = CapabilityLedger(max_depth=1)
    target = campaign.spec.targets[0].endpoint
    root = ledger.issue_root(
        campaign,
        subject="agent:supervisor",
        tools={"mock.agent-probe"},
        targets={target},
    )
    observed = ledger.record(root.grant_id)

    observed.remaining_calls = 0
    observed.revoked = True
    observed.grant.tools.add("shell.execute")

    authoritative = ledger.record(root.grant_id)
    assert authoritative.remaining_calls == root.max_calls
    assert not authoritative.revoked
    assert authoritative.grant.tools == {"mock.agent-probe"}
    assert ledger.can_consume(root.grant_id)


@pytest.mark.parametrize("max_calls", [True, 1.0, "1"])
def test_delegation_rejects_coercible_non_integer_call_authority(max_calls: object) -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    ledger = CapabilityLedger(max_depth=1)
    target = campaign.spec.targets[0].endpoint
    root = ledger.issue_root(
        campaign,
        subject="agent:supervisor",
        tools={"mock.agent-probe"},
        targets={target},
    )

    with pytest.raises(CapabilityError, match="non-negative integer"):
        ledger.delegate(
            root.grant_id,
            subject="agent:specialist",
            tools={"mock.agent-probe"},
            targets={target},
            max_risk_tier=ToolRiskTier.T1,
            max_calls=max_calls,  # type: ignore[arg-type]
        )
