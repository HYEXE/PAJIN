import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from typing import Any, cast
from urllib.parse import quote, quote_plus

import pytest

from pajin.runtime.secrets import (
    SecretBroker,
    SecretLeaseStatus,
    SecretMaterial,
    redact_secret_values,
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


def test_exact_secret_lease_id_preserves_normal_lease_semantics() -> None:
    now = datetime(2026, 7, 12, tzinfo=UTC)
    broker = SecretBroker(clock=lambda: now)
    broker.register("provider/example/api-key", "exact-id-secret")

    lease = broker.issue_exact(
        "provider/example/api-key",
        lease_id=f"lease_{'a' * 32}",
        audience="worker:exact",
        binding="provider-api-key",
        scope="claim_exact",
        ttl_seconds=20,
        max_uses=1,
    )

    assert lease.lease_id == f"lease_{'a' * 32}"
    assert lease.issued_at == now
    assert lease.expires_at == now + timedelta(seconds=20)
    material = broker.materialize(
        lease.lease_id,
        audience="worker:exact",
        scope="claim_exact",
    )
    assert material.value == "exact-id-secret"
    with pytest.raises(PermissionError, match="no remaining uses"):
        broker.materialize(
            lease.lease_id,
            audience="worker:exact",
            scope="claim_exact",
        )


def test_revoking_unmaterialized_exact_lease_eliminates_remaining_authority() -> None:
    now = datetime(2026, 7, 12, tzinfo=UTC)
    broker = SecretBroker(clock=lambda: now)
    broker.register("provider/example/api-key", "exact-id-secret")
    lease = broker.issue_exact(
        "provider/example/api-key",
        lease_id=f"lease_{'c' * 32}",
        audience="worker:exact",
        binding="provider-api-key",
        scope="claim_exact",
        ttl_seconds=20,
        max_uses=1,
    )

    revoked = broker.revoke(
        lease.lease_id,
        "cleanup before materialization",
        scope="claim_exact",
    )
    inspected = broker.inspect(
        lease.lease_id,
        audience="worker:exact",
        scope="claim_exact",
    )

    assert revoked.status is SecretLeaseStatus.REVOKED
    assert revoked.remaining_uses == 0
    assert inspected == revoked


@pytest.mark.parametrize(
    "lease_id",
    [
        "",
        "lease_" + "a" * 31,
        "lease_" + "a" * 33,
        "lease_" + "A" * 32,
        "lease_" + "g" * 32,
        "other_" + "a" * 32,
        "lease_" + "a" * 32 + "\n",
    ],
)
def test_exact_secret_lease_id_rejects_noncanonical_values(lease_id: str) -> None:
    broker = SecretBroker()
    broker.register("provider/example/api-key", "exact-id-secret")

    with pytest.raises(ValueError, match=r"lease_\[a-f0-9\]"):
        broker.issue_exact(
            "provider/example/api-key",
            lease_id=lease_id,
            audience="worker:exact",
            binding="provider-api-key",
        )


def test_exact_secret_lease_id_rejects_non_string_value() -> None:
    broker = SecretBroker()
    broker.register("provider/example/api-key", "exact-id-secret")

    with pytest.raises(TypeError, match="must be a string"):
        broker.issue_exact(
            "provider/example/api-key",
            lease_id=cast(Any, 1),
            audience="worker:exact",
            binding="provider-api-key",
        )


def test_exact_secret_lease_id_duplicate_is_atomic_under_concurrent_issuance() -> None:
    broker = SecretBroker()
    broker.register("provider/example/api-key", "exact-id-secret")
    lease_id = f"lease_{'b' * 32}"
    ready = Barrier(2)

    def issue() -> str:
        ready.wait()
        try:
            lease = broker.issue_exact(
                "provider/example/api-key",
                lease_id=lease_id,
                audience="worker:exact",
                binding="provider-api-key",
            )
        except ValueError:
            return "duplicate"
        return lease.status.value

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in (pool.submit(issue), pool.submit(issue))]

    assert sorted(results) == ["active", "duplicate"]
    assert [item["lease_id"] for item in broker.snapshot()] == [lease_id]


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


def test_secret_lease_inspection_rechecks_identity_without_consuming_material() -> None:
    current = [datetime(2026, 7, 12, tzinfo=UTC)]
    broker = SecretBroker(clock=lambda: current[0])
    broker.register("provider/example/api-key", "inspection-secret")
    lease = broker.issue(
        "provider/example/api-key",
        audience="worker:cloud",
        binding="provider-api-key",
        scope="run_cloud",
        ttl_seconds=1,
    )

    inspected = broker.inspect(
        lease.lease_id,
        audience="worker:cloud",
        scope="run_cloud",
    )
    assert inspected == lease
    assert inspected is not lease
    assert inspected.remaining_uses == 1

    with pytest.raises(PermissionError, match="audience mismatch"):
        broker.inspect(
            lease.lease_id,
            audience="worker:other",
            scope="run_cloud",
        )
    with pytest.raises(PermissionError, match="scope mismatch"):
        broker.inspect(
            lease.lease_id,
            audience="worker:cloud",
            scope="run_other",
        )

    current[0] += timedelta(seconds=2)
    expired = broker.inspect(
        lease.lease_id,
        audience="worker:cloud",
        scope="run_cloud",
    )
    assert expired.status is SecretLeaseStatus.EXPIRED
    assert expired.remaining_uses == 1


def test_secret_lease_run_scopes_isolate_materialization_revocation_and_snapshots() -> None:
    now = datetime(2026, 7, 12, tzinfo=UTC)
    broker = SecretBroker(clock=lambda: now)
    broker.register("provider/example/api-key", "scope-isolated-secret")
    first = broker.issue(
        "provider/example/api-key",
        audience="worker:first",
        binding="provider-api-key",
        scope="run_first",
    )
    second = broker.issue(
        "provider/example/api-key",
        audience="worker:second",
        binding="provider-api-key",
        scope="run_second",
    )

    with pytest.raises(PermissionError, match="scope mismatch"):
        broker.materialize(
            first.lease_id,
            audience="worker:first",
            scope="run_second",
        )
    with pytest.raises(PermissionError, match="scope mismatch"):
        broker.revoke(first.lease_id, "wrong Run", scope="run_second")

    revoked = broker.revoke_scope("run_second", "second Run cancelled")

    assert [lease.lease_id for lease in revoked] == [second.lease_id]
    assert broker.snapshot_scope("run_first") == [
        {
            **first.model_dump(mode="json"),
            "status": "active",
            "revoked_reason": None,
        }
    ]
    second_snapshot = broker.snapshot_scope("run_second")
    assert [item["lease_id"] for item in second_snapshot] == [second.lease_id]
    assert second_snapshot[0]["status"] == "revoked"
    material = broker.materialize(
        first.lease_id,
        audience="worker:first",
        scope="run_first",
    )
    assert material.value == "scope-isolated-secret"
    assert len(broker.snapshot()) == 2


@pytest.mark.parametrize("scope", ["", " run_first", "run/first", "run\nfirst"])
def test_secret_lease_scope_requires_a_safe_identifier(scope: str) -> None:
    broker = SecretBroker()
    broker.register("provider/example/api-key", "scope-validation-secret")

    with pytest.raises(ValueError, match="safe identifier"):
        broker.issue(
            "provider/example/api-key",
            audience="worker",
            binding="provider-api-key",
            scope=scope,
        )


def test_short_secret_redaction_never_expands_untrusted_output() -> None:
    broker = SecretBroker()

    with pytest.raises(ValueError, match="between 1 and 16384"):
        broker.register("provider/example/api-key", "")
    material = SecretMaterial(lease_id="lease_test", binding="provider-api-key", value="x")
    untrusted_output = "x" * 100_000

    redacted = redact_text(untrusted_output, [material])

    assert "x" not in redacted
    assert len(redacted) == len(untrusted_output)


def test_short_transformed_secret_variants_do_not_mask_common_unrelated_text() -> None:
    material = SecretMaterial(lease_id="lease_test", binding="provider-api-key", value="x")

    redacted = redact_text("numeric=78 encoded=eA== value=x", [material])

    assert redacted == "numeric=78 encoded=eA== value=*"


def test_secret_values_must_be_utf8_encodable() -> None:
    broker = SecretBroker()

    with pytest.raises(ValueError, match="UTF-8"):
        broker.register("provider/example/api-key", "\ud800")
    with pytest.raises(ValueError, match="UTF-8"):
        SecretMaterial(lease_id="lease_test", binding="provider-api-key", value="\udfff")
    with pytest.raises(ValueError, match="UTF-8"):
        broker.register("provider/\ud800", "valid-secret")
    with pytest.raises(ValueError, match="UTF-8"):
        SecretBroker.fingerprint("provider/\udfff")


def test_redaction_covers_common_serializations_and_mapping_keys() -> None:
    secret = 'p\N{LATIN SMALL LETTER A WITH DIAERESIS}ss word/"token-1234'
    material = SecretMaterial(
        lease_id="lease_test",
        binding="provider-api-key",
        value=secret,
    )
    encoded = secret.encode("utf-8")
    variants = {
        secret,
        encoded.hex(),
        encoded.hex().upper(),
        base64.b64encode(encoded).decode("ascii"),
        base64.b64encode(encoded).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(encoded).decode("ascii"),
        base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
        quote(secret, safe=""),
        quote_plus(secret, safe=""),
        json.dumps(secret, ensure_ascii=False)[1:-1],
        json.dumps(secret, ensure_ascii=True)[1:-1],
    }

    standard_base64 = base64.b64encode(encoded).decode("ascii")
    redacted = redact_text(" | ".join(sorted(variants)), [material])
    redacted_mapping = redact_value({secret: {"encoded": standard_base64}}, [material])

    assert all(variant not in redacted for variant in variants)
    assert "<redacted-secret>" in redacted
    assert redacted_mapping == {"<redacted-secret>": {"encoded": "<redacted-secret>"}}


def test_secret_value_redaction_matches_material_redaction() -> None:
    secret = 'p\N{LATIN SMALL LETTER A WITH DIAERESIS}ss word/"token-1234'
    material = SecretMaterial(
        lease_id="lease_test",
        binding="browser-session",
        value=secret,
    )
    encoded = secret.encode("utf-8")
    variants = {
        secret,
        encoded.hex(),
        encoded.hex().upper(),
        base64.b64encode(encoded).decode("ascii"),
        base64.b64encode(encoded).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(encoded).decode("ascii"),
        base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
        quote(secret, safe=""),
        quote_plus(secret, safe=""),
        json.dumps(secret, ensure_ascii=False)[1:-1],
        json.dumps(secret, ensure_ascii=True)[1:-1],
    }
    reflected = " | ".join(sorted(variants))

    redacted = redact_secret_values(reflected, [secret])

    assert redacted == redact_text(reflected, [material])
    assert all(variant not in redacted for variant in variants)
    assert "<redacted-secret>" in redacted


def test_secret_value_redaction_rejects_oversized_material_before_expansion() -> None:
    with pytest.raises(ValueError, match="between 1 and 16384"):
        redact_secret_values("safe metadata", ["x" * 16_385])


def test_secret_value_redaction_handles_equivalent_encoded_forms() -> None:
    secret = "browser.user+tag@example.test"
    encoded_hex = secret.encode().hex()
    mixed_case_hex = "".join(
        character.upper() if index % 2 else character.lower()
        for index, character in enumerate(encoded_hex)
    )
    selective_percent = secret.replace(".", "%2e").replace("+", "%2B").replace("@", "%40")
    double_percent = selective_percent.replace("%", "%25")
    deeply_nested_percent = selective_percent
    for _ in range(3):
        deeply_nested_percent = quote(deeply_nested_percent, safe="")

    for reflected in (
        mixed_case_hex,
        selective_percent,
        double_percent,
        deeply_nested_percent,
    ):
        redacted = redact_secret_values(f"metadata={reflected}", [secret])

        assert reflected not in redacted
        assert secret not in redacted


@pytest.mark.parametrize("secret", ["<redacted-secret>", "********"])
def test_secret_value_redaction_avoids_replacement_collision(secret: str) -> None:
    reflected = f"metadata={secret}"

    redacted = redact_secret_values(reflected, [secret])

    assert redacted != reflected
    assert secret not in redacted
