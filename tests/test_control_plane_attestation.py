from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from typer.testing import CliRunner

import pajin.cli as cli
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.attestation import (
    PortableReplayAttestationBundle,
    ReplayAttestationKeyState,
    ReplayAttestationTrustAnchor,
    ReplayAttestationVerificationError,
    ReplayAttestationVerificationKey,
    ReplayAttestor,
    load_portable_replay_attestation_file,
    portable_replay_attestation_bytes,
    public_key_base64url,
    verify_portable_replay_attestation,
)
from pajin.control_plane.database import ControlPlaneRepository
from pajin.control_plane.errors import StateConflict
from pajin.control_plane.models import (
    ArtifactLocator,
    ArtifactRef,
    CreateReplayBatchRequest,
    Principal,
    PrincipalRole,
    ReplayClaimProjectionInputAuthority,
    ReplayClaimProjectionItemAuthority,
)
from pajin.control_plane.security import CheckpointSigner
from pajin.control_plane.service import ControlPlaneService
from pajin.domain.replay import ReplayClaimBinding
from pajin.domain.validation import AtomicClaimType
from pajin.replay.tickets import replay_context_digest

_ISSUED_AT = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
_OLD_PRIVATE_KEY = bytes(range(32))
_NEW_PRIVATE_KEY = bytes(range(32, 64))


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _artifact(label: str, *, run_id: str) -> ArtifactRef:
    return ArtifactRef(
        artifact_id=f"artifact_{_digest(label)[:32]}",
        repository_version=1,
        media_type="application/vnd.pajin.run+directory",
        schema_kind="pajin.replay.output.sealed.v1",
        byte_length=100,
        content_digest=_digest(f"{label}:content"),
        producer_run_id=run_id,
        run_id=run_id,
        integrity_root_digest=_digest(f"{label}:root"),
        created_by="control-plane:test",
    )


def _authority() -> ReplayClaimProjectionInputAuthority:
    batch_id = f"replay-batch_{_digest('batch')[:32]}"
    candidate_id = "candidate-portable-attestation"
    candidate_digest = _digest("candidate")
    candidate_claim_digest = _digest("candidate-claim")
    items: list[ReplayClaimProjectionItemAuthority] = []
    for ordinal, claim_type in enumerate(AtomicClaimType):
        run_id = f"run_{_digest(f'run:{ordinal}')[:32]}"
        claim_id = f"claim-{claim_type.value}"
        items.append(
            ReplayClaimProjectionItemAuthority(
                ordinal=ordinal,
                item_id=f"replay-item_{_digest(f'item:{ordinal}')[:32]}",
                ticket_id=f"replay-ticket_{_digest(f'ticket:{ordinal}')[:32]}",
                finalization_id=(f"replay-finalization_{_digest(f'finalization:{ordinal}')[:32]}"),
                replay_run_id=run_id,
                compilation_digest=_digest(f"compilation:{ordinal}"),
                output=_artifact(f"output:{ordinal}", run_id=run_id),
                artifact_set_digest=_digest(f"artifact-set:{ordinal}"),
                receipt_seal_root_digest=_digest(f"receipt:{ordinal}"),
                gate_decision_digest=_digest(f"gate:{ordinal}"),
                result_digest=_digest(f"result:{ordinal}"),
                finalized_at=_ISSUED_AT - timedelta(minutes=1),
                candidate_id=candidate_id,
                candidate_digest=candidate_digest,
                claim=ReplayClaimBinding(
                    candidate_claim_digest=candidate_claim_digest,
                    claim_id=claim_id,
                    claim_digest=_digest(claim_id),
                    claim_type=claim_type,
                    statement=f"{claim_type.value} statement",
                ),
            )
        )
    return ReplayClaimProjectionInputAuthority(
        batch_id=batch_id,
        source=_artifact(
            "source",
            run_id=f"run_{_digest('source-run')[:32]}",
        ),
        batch_cas_version=7,
        items=items,
    )


def _verification_key(
    key_id: str,
    private_key: bytes,
    *,
    state: ReplayAttestationKeyState,
    not_after: datetime | None = None,
    revoked_at: datetime | None = None,
) -> ReplayAttestationVerificationKey:
    return ReplayAttestationVerificationKey(
        key_id=key_id,
        public_key_base64url=public_key_base64url(private_key),
        state=state,
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=not_after,
        revoked_at=revoked_at,
    )


def _anchor(
    *keys: ReplayAttestationVerificationKey,
) -> ReplayAttestationTrustAnchor:
    return ReplayAttestationTrustAnchor(
        trust_domain="security.example/pajin-production",
        issuer="example-security-control-plane",
        keys=sorted(keys, key=lambda key: key.key_id),
    )


def _bundle() -> tuple[PortableReplayAttestationBundle, ReplayAttestationTrustAnchor]:
    anchor = _anchor(
        _verification_key(
            "key-2026-a",
            _OLD_PRIVATE_KEY,
            state=ReplayAttestationKeyState.ACTIVE,
        )
    )
    authority = _authority()
    bundle = ReplayAttestor.from_private_key_bytes(
        active_key_id="key-2026-a",
        private_key=_OLD_PRIVATE_KEY,
        trust_anchor=anchor,
    ).attest(
        authority,
        authority_digest=replay_context_digest(authority.model_dump(mode="json", by_alias=True)),
        issued_at=_ISSUED_AT,
    )
    return bundle, anchor


def test_portable_replay_attestation_verifies_off_host_from_explicit_anchor(
    tmp_path: Path,
) -> None:
    bundle, anchor = _bundle()
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_bytes(portable_replay_attestation_bytes(bundle))

    loaded = load_portable_replay_attestation_file(bundle_path)
    verified = verify_portable_replay_attestation(loaded, trust_anchor=anchor)

    assert verified.batch_id == bundle.statement.batch_id
    assert verified.key_id == "key-2026-a"
    assert verified.key_state is ReplayAttestationKeyState.ACTIVE
    assert verified.receipt_count == len(AtomicClaimType)
    assert verified.trust_anchor_digest == anchor.digest


def test_portable_replay_attestation_rejects_statement_and_signature_tampering() -> None:
    bundle, anchor = _bundle()
    tampered_statement = bundle.statement.model_copy(update={"issuer": "attacker-control-plane"})
    tampered_bundle = bundle.model_copy(update={"statement": tampered_statement})

    with pytest.raises(
        ReplayAttestationVerificationError,
        match="issuer or trust domain",
    ):
        verify_portable_replay_attestation(tampered_bundle, trust_anchor=anchor)

    replacement_signature = ("A" if bundle.signature_base64url[0] != "A" else "B") + (
        bundle.signature_base64url[1:]
    )
    signature_tampered = bundle.model_copy(update={"signature_base64url": replacement_signature})
    with pytest.raises(
        ReplayAttestationVerificationError,
        match="signature verification failed",
    ):
        verify_portable_replay_attestation(signature_tampered, trust_anchor=anchor)


def test_portable_replay_attestation_accepts_retired_key_after_rotation() -> None:
    bundle, _original_anchor = _bundle()
    rotated_anchor = _anchor(
        _verification_key(
            "key-2026-a",
            _OLD_PRIVATE_KEY,
            state=ReplayAttestationKeyState.RETIRED,
            not_after=_ISSUED_AT + timedelta(hours=1),
        ),
        _verification_key(
            "key-2026-b",
            _NEW_PRIVATE_KEY,
            state=ReplayAttestationKeyState.ACTIVE,
        ),
    )

    verified = verify_portable_replay_attestation(
        bundle,
        trust_anchor=rotated_anchor,
    )

    assert verified.key_state is ReplayAttestationKeyState.RETIRED


def test_replay_attestation_rejects_retired_key_without_bounded_window() -> None:
    with pytest.raises(ValidationError, match="retired Replay attestation key requires not_after"):
        _verification_key(
            "key-2026-a",
            _OLD_PRIVATE_KEY,
            state=ReplayAttestationKeyState.RETIRED,
        )


def test_replay_attestor_rejects_issue_time_outside_active_key_window() -> None:
    anchor = _anchor(
        _verification_key(
            "key-2026-a",
            _OLD_PRIVATE_KEY,
            state=ReplayAttestationKeyState.ACTIVE,
            not_after=_ISSUED_AT,
        )
    )
    attestor = ReplayAttestor.from_private_key_bytes(
        active_key_id="key-2026-a",
        private_key=_OLD_PRIVATE_KEY,
        trust_anchor=anchor,
    )

    with pytest.raises(ValueError, match="signing key is not valid"):
        attestor.attest(
            _authority(),
            authority_digest=replay_context_digest(
                _authority().model_dump(mode="json", by_alias=True)
            ),
            issued_at=_ISSUED_AT,
        )


def test_portable_replay_attestation_rejects_revoked_key() -> None:
    bundle, _original_anchor = _bundle()
    revoked_anchor = _anchor(
        _verification_key(
            "key-2026-a",
            _OLD_PRIVATE_KEY,
            state=ReplayAttestationKeyState.REVOKED,
            revoked_at=_ISSUED_AT + timedelta(hours=1),
        ),
        _verification_key(
            "key-2026-b",
            _NEW_PRIVATE_KEY,
            state=ReplayAttestationKeyState.ACTIVE,
        ),
    )

    with pytest.raises(ReplayAttestationVerificationError, match="key is revoked"):
        verify_portable_replay_attestation(bundle, trust_anchor=revoked_anchor)


def test_replay_attestor_rejects_private_key_not_pinned_by_anchor() -> None:
    anchor = _anchor(
        _verification_key(
            "key-2026-a",
            _OLD_PRIVATE_KEY,
            state=ReplayAttestationKeyState.ACTIVE,
        )
    )

    with pytest.raises(ValueError, match="does not match its trust anchor"):
        ReplayAttestor.from_private_key_bytes(
            active_key_id="key-2026-a",
            private_key=_NEW_PRIVATE_KEY,
            trust_anchor=anchor,
        )


def test_replay_attestation_bundle_parser_rejects_digest_tampering() -> None:
    bundle, _anchor_value = _bundle()
    raw = bundle.model_dump(mode="json")
    raw["statement_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="statement digest is inconsistent"):
        PortableReplayAttestationBundle.model_validate(raw)


def test_portable_attestation_requires_claim_projection_and_configured_signer() -> None:
    locator = ArtifactLocator(artifact_id=f"artifact_{'1' * 32}", repository_version=1)
    with pytest.raises(ValidationError, match="requires a Claim projection"):
        CreateReplayBatchRequest(
            source=locator,
            portable_attestation=True,
            idempotency_key="portable-without-claim",
        )

    request = CreateReplayBatchRequest(
        source=locator,
        claim_projection=True,
        portable_attestation=True,
        idempotency_key="portable-without-signer",
    )
    repository = ControlPlaneRepository("sqlite+pysqlite:///:memory:")
    service = ControlPlaneService(
        repository,
        CheckpointSigner(
            active_key_id="checkpoint-v1",
            keys={"checkpoint-v1": b"checkpoint-signing-key-at-least-32-bytes"},
        ),
    )
    try:
        with pytest.raises(StateConflict, match="signer is not configured"):
            service.create_replay_batch(request, actor="operator")
    finally:
        repository.close()


def _required_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", "o" * 32)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", "a" * 32)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", "w" * 32)
    monkeypatch.setenv("PAJIN_CP_CHECKPOINT_KEY", "checkpoint-key-that-is-at-least-32-bytes")


def test_replay_attestation_environment_loads_complete_key_and_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _required_environment(monkeypatch)
    anchor = _anchor(
        _verification_key(
            "key-2026-a",
            _OLD_PRIVATE_KEY,
            state=ReplayAttestationKeyState.ACTIVE,
        )
    )
    monkeypatch.setenv("PAJIN_CP_REPLAY_ATTESTATION_KEY_ID", "key-2026-a")
    monkeypatch.setenv(
        "PAJIN_CP_REPLAY_ATTESTATION_PRIVATE_KEY",
        base64.urlsafe_b64encode(_OLD_PRIVATE_KEY).decode("ascii").rstrip("="),
    )
    monkeypatch.setenv(
        "PAJIN_CP_REPLAY_ATTESTATION_TRUST_ANCHOR",
        json.dumps(anchor.model_dump(mode="json"), separators=(",", ":")),
    )

    settings = ControlPlaneSettings.from_env()

    assert settings.replay_attestation_key_id == "key-2026-a"
    assert settings.replay_attestation_private_key == _OLD_PRIVATE_KEY
    assert settings.replay_attestation_trust_anchor == anchor


def test_replay_attestation_environment_rejects_partial_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _required_environment(monkeypatch)
    monkeypatch.setenv("PAJIN_CP_REPLAY_ATTESTATION_KEY_ID", "key-2026-a")

    with pytest.raises(RuntimeError, match="must be configured together"):
        ControlPlaneSettings.from_env()


def test_control_plane_exposes_public_anchor_without_private_key(
    tmp_path: Path,
) -> None:
    anchor = _anchor(
        _verification_key(
            "key-2026-a",
            _OLD_PRIVATE_KEY,
            state=ReplayAttestationKeyState.ACTIVE,
        )
    )
    operator_token = "operator-token-that-is-at-least-32-bytes"
    app = create_app(
        ControlPlaneSettings(
            database_url=f"sqlite:///{(tmp_path / 'control-plane.db').as_posix()}",
            credentials={
                operator_token: Principal(
                    subject="operator",
                    roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
                ),
                "approver-token-that-is-at-least-32-bytes": Principal(
                    subject="approver",
                    roles=frozenset({PrincipalRole.APPROVER}),
                ),
                "worker-token-that-is-at-least-32-bytes": Principal(
                    subject="worker",
                    roles=frozenset({PrincipalRole.WORKER}),
                ),
            },
            checkpoint_keys={"checkpoint-v1": b"checkpoint-signing-key-at-least-32-bytes"},
            active_checkpoint_key_id="checkpoint-v1",
            replay_attestation_key_id="key-2026-a",
            replay_attestation_private_key=_OLD_PRIVATE_KEY,
            replay_attestation_trust_anchor=anchor,
        )
    )

    with TestClient(app) as client:
        response = client.get(
            "/v1/replay/attestation/trust-anchor",
            headers={"Authorization": f"Bearer {operator_token}"},
        )

    assert response.status_code == 200
    assert response.json() == anchor.model_dump(mode="json")
    assert base64.urlsafe_b64encode(_OLD_PRIVATE_KEY).decode("ascii") not in response.text


def test_replay_attestation_cli_requires_explicit_anchor_and_reports_digest(
    tmp_path: Path,
) -> None:
    bundle, anchor = _bundle()
    bundle_path = tmp_path / "bundle.json"
    anchor_path = tmp_path / "trust-anchor.json"
    bundle_path.write_bytes(portable_replay_attestation_bytes(bundle))
    anchor_path.write_text(
        json.dumps(anchor.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli.app,
        [
            "replay-attestation-verify",
            str(bundle_path),
            "--trust-anchor",
            str(anchor_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "VALID" in result.output
    assert bundle.statement.input_authority_digest in result.output
    assert anchor.digest in result.output
