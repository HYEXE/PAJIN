from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from pajin.control_plane.api import ControlPlaneSettings
from pajin.replay.target_attestation import (
    TargetAttestationKeyState,
    TargetAttestationTrustAnchor,
    TargetAttestationVerificationKey,
    TargetExecutionAttestor,
    TargetExecutionChallenge,
    canonical_target_json,
    derive_target_execution_challenge,
    target_public_key_base64url,
    verify_target_execution_receipt,
)


def _authority(
    now: datetime,
) -> tuple[TargetAttestationTrustAnchor, TargetExecutionAttestor]:
    private_key = bytes(range(32))
    anchor = TargetAttestationTrustAnchor(
        trust_domain="pajin.example/targets",
        issuer="PAJIN deterministic AI target",
        target_profile="kisa-lab-v1",
        keys=[
            TargetAttestationVerificationKey(
                key_id="target-key-2026-01",
                public_key_base64url=target_public_key_base64url(private_key),
                state=TargetAttestationKeyState.ACTIVE,
                not_before=now - timedelta(minutes=1),
            )
        ],
    )
    return (
        anchor,
        TargetExecutionAttestor.from_private_key_bytes(
            active_key_id="target-key-2026-01",
            private_key=private_key,
            trust_anchor=anchor,
            clock=lambda: now,
        ),
    )


def _challenge(
    now: datetime,
    *,
    permit_digest: str = "a" * 64,
) -> TargetExecutionChallenge:
    return derive_target_execution_challenge(
        permit_digest=permit_digest,
        replay_request_id=f"tool_replay_{'1' * 32}",
        batch_id=f"replay-batch_{'2' * 32}",
        item_id=f"replay-item_{'3' * 32}",
        ticket_id=f"replay-ticket_{'4' * 32}",
        fencing_value=7,
        call_ordinal=1,
        target="http://ai-target:8080/v1/chat",
        method="POST",
        compiled_argument_digest="b" * 64,
        issued_at=now,
        expires_at=now + timedelta(seconds=20),
    )


def test_target_challenge_is_deterministic_and_permit_bound() -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)

    first = _challenge(now)
    second = _challenge(now)
    changed = _challenge(now, permit_digest="c" * 64)

    assert first == second
    assert changed.challenge_id != first.challenge_id
    assert changed.digest != first.digest


def test_target_receipt_signature_rejects_statement_tampering() -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    anchor, attestor = _authority(now)
    challenge = _challenge(now)
    receipt = attestor.attest(
        {
            "challenge_id": challenge.challenge_id,
            "challenge_sha256": challenge.digest,
            "permit_digest": challenge.permit_digest,
            "replay_request_id": challenge.replay_request_id,
            "batch_id": challenge.batch_id,
            "item_id": challenge.item_id,
            "ticket_id": challenge.ticket_id,
            "fencing_value": challenge.fencing_value,
            "call_ordinal": challenge.call_ordinal,
            "exchange_ordinal": 1,
            "target_sha256": challenge.target_sha256,
            "method": challenge.method,
            "request_json_sha256": "d" * 64,
            "response_payload_sha256": "e" * 64,
            "status": 200,
        }
    )

    assert verify_target_execution_receipt(receipt, trust_anchor=anchor) == ("target-key-2026-01")

    changed_statement = receipt.statement.model_copy(update={"request_json_sha256": "f" * 64})
    tampered = receipt.model_copy(
        update={
            "statement": changed_statement,
            "statement_sha256": sha256(
                canonical_target_json(changed_statement.model_dump(mode="json"))
            ).hexdigest(),
        }
    )
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_target_execution_receipt(tampered, trust_anchor=anchor)


def test_target_receipt_rejects_revoked_signing_key() -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    anchor, attestor = _authority(now)
    challenge = _challenge(now)
    receipt = attestor.attest(
        {
            "challenge_id": challenge.challenge_id,
            "challenge_sha256": challenge.digest,
            "permit_digest": challenge.permit_digest,
            "replay_request_id": challenge.replay_request_id,
            "batch_id": challenge.batch_id,
            "item_id": challenge.item_id,
            "ticket_id": challenge.ticket_id,
            "fencing_value": challenge.fencing_value,
            "call_ordinal": challenge.call_ordinal,
            "exchange_ordinal": 1,
            "target_sha256": challenge.target_sha256,
            "method": challenge.method,
            "request_json_sha256": "d" * 64,
            "response_payload_sha256": "e" * 64,
            "status": 200,
        }
    )
    replacement_private_key = bytes(range(32, 64))
    revoked_anchor = TargetAttestationTrustAnchor(
        trust_domain=anchor.trust_domain,
        issuer=anchor.issuer,
        target_profile=anchor.target_profile,
        keys=[
            TargetAttestationVerificationKey(
                key_id="target-key-2026-01",
                public_key_base64url=anchor.keys[0].public_key_base64url,
                state=TargetAttestationKeyState.REVOKED,
                not_before=now - timedelta(minutes=1),
                revoked_at=now + timedelta(seconds=1),
            ),
            TargetAttestationVerificationKey(
                key_id="target-key-2026-02",
                public_key_base64url=target_public_key_base64url(replacement_private_key),
                state=TargetAttestationKeyState.ACTIVE,
                not_before=now,
            ),
        ],
    )

    with pytest.raises(ValueError, match="key is revoked"):
        verify_target_execution_receipt(receipt, trust_anchor=revoked_anchor)


def test_control_plane_loads_only_target_public_trust_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    anchor, _attestor = _authority(now)
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", "o" * 32)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", "a" * 32)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", "w" * 32)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "checkpoint-key-that-is-at-least-32-bytes",
    )
    monkeypatch.setenv(
        "PAJIN_CP_TARGET_ATTESTATION_TRUST_ANCHOR",
        json.dumps(anchor.model_dump(mode="json"), separators=(",", ":")),
    )

    settings = ControlPlaneSettings.from_env()

    assert settings.target_attestation_trust_anchor == anchor
