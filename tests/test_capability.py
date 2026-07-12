from datetime import UTC, datetime, timedelta
from pathlib import Path

from pajin.domain.manifest import load_manifest
from pajin.domain.models import CapabilityGrant, ToolRiskTier
from pajin.policy.capability import CapabilityLedger


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
