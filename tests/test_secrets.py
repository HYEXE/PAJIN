from datetime import UTC, datetime, timedelta

import pytest

from pajin.runtime.secrets import (
    SecretBroker,
    SecretLeaseStatus,
    redact_text,
    redact_value,
)


def test_secret_lease_is_one_use_audience_bound_and_redacted() -> None:
    now = datetime(2026, 7, 12, tzinfo=UTC)
    broker = SecretBroker(clock=lambda: now)
    broker.register("provider/example/api-key", "longer-secret-value")
    lease = broker.issue(
        "provider/example/api-key",
        audience="agent:worker",
        binding="provider-api-key",
        ttl_seconds=30,
    )

    with pytest.raises(PermissionError, match="audience mismatch"):
        broker.materialize(lease.lease_id, audience="another-worker")

    material = broker.materialize(lease.lease_id, audience="agent:worker")

    assert "longer-secret-value" not in repr(material)
    assert redact_text(f"Bearer {material.value}", [material]) == "Bearer <redacted-secret>"
    assert redact_value({"nested": [material.value]}, [material]) == {
        "nested": ["<redacted-secret>"]
    }
    with pytest.raises(PermissionError, match="no remaining uses"):
        broker.materialize(lease.lease_id, audience="agent:worker")

    revoked = broker.revoke(lease.lease_id, "worker completed")
    snapshot = broker.snapshot()

    assert revoked.status is SecretLeaseStatus.REVOKED
    assert revoked.remaining_uses == 0
    assert "provider/example/api-key" not in str(snapshot)
    assert "longer-secret-value" not in str(snapshot)


def test_secret_lease_expires_before_materialization() -> None:
    current = [datetime(2026, 7, 12, tzinfo=UTC)]
    broker = SecretBroker(clock=lambda: current[0])
    broker.register("provider/example/api-key", "test-secret")
    lease = broker.issue(
        "provider/example/api-key",
        audience="worker",
        binding="provider-api-key",
        ttl_seconds=1,
    )
    current[0] += timedelta(seconds=2)

    with pytest.raises(PermissionError, match="expired"):
        broker.materialize(lease.lease_id, audience="worker")

    assert broker.snapshot()[0]["status"] == "expired"
