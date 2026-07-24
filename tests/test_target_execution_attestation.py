from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import TypeAdapter
from sqlalchemy import select

from pajin.control_plane import api as control_plane_api
from pajin.control_plane.api import (
    ControlPlaneSettings,
    _load_target_attestation_registry_bundle,
    create_app,
)
from pajin.control_plane.database import (
    ControlPlaneRepository,
    TargetAttestationRegistryVersionRecord,
)
from pajin.control_plane.errors import StateConflict
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.control_plane.security import CheckpointSigner
from pajin.control_plane.service import ControlPlaneService, _target_transport_binding_matches
from pajin.target_attestation import (
    TargetAttestationKeyState,
    TargetAttestationRegistryBundle,
    TargetAttestationRegistrySigner,
    TargetAttestationRegistryTrustAnchor,
    TargetAttestationTrustAnchor,
    TargetAttestationTrustRegistry,
    TargetAttestationTrustRegistryEntry,
    TargetAttestationVerificationKey,
    TargetExecutionAttestor,
    TargetExecutionChallenge,
    TargetExecutionTLSBinding,
    TargetExecutionTLSBindingV2,
    TargetExecutionTLSBindingV3,
    TargetExecutionTransportBinding,
    TargetExecutionVerificationSummary,
    canonical_target_json,
    derive_target_execution_challenge,
    parse_target_attestation_registry_bundle,
    parse_target_attestation_trust_registry,
    target_public_key_base64url,
    verify_target_attestation_registry_bundle,
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


def _registry_distribution_authority(
    now: datetime,
) -> tuple[TargetAttestationRegistryTrustAnchor, TargetAttestationRegistrySigner]:
    private_key = bytes(range(32, 64))
    anchor = TargetAttestationRegistryTrustAnchor(
        trust_domain="pajin.example/target-registry",
        issuer="PAJIN target registry operator",
        keys=[
            TargetAttestationVerificationKey(
                key_id="registry-key-2026-01",
                public_key_base64url=target_public_key_base64url(private_key),
                state=TargetAttestationKeyState.ACTIVE,
                not_before=now - timedelta(minutes=1),
            )
        ],
    )
    return (
        anchor,
        TargetAttestationRegistrySigner.from_private_key_bytes(
            active_key_id="registry-key-2026-01",
            private_key=private_key,
            trust_anchor=anchor,
        ),
    )


def _signed_registry_bundle(
    now: datetime,
    *,
    sequence: int = 1,
    previous_bundle_sha256: str | None = None,
    registry_id: str = "pajin-targets-2026-07",
) -> tuple[TargetAttestationRegistryTrustAnchor, TargetAttestationRegistryBundle]:
    target_anchor, _target_attestor = _authority(now)
    distribution_anchor, signer = _registry_distribution_authority(now)
    registry = TargetAttestationTrustRegistry(
        api_version="pajin.replay.target-attestation-trust-registry/v3",
        registry_id=registry_id,
        entries=[
            TargetAttestationTrustRegistryEntry(
                target="https://ai.example.test/v1/chat",
                trust_anchor=target_anchor,
                tls_leaf_spki_sha256="c" * 64,
                retiring_tls_leaf_spki_sha256="d" * 64,
                retiring_tls_leaf_spki_not_after=now + timedelta(hours=1),
            )
        ],
    )
    return (
        distribution_anchor,
        signer.sign(
            registry=registry,
            sequence=sequence,
            previous_bundle_sha256=previous_bundle_sha256,
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(days=1),
        ),
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


def test_target_trust_registry_routes_only_exact_canonical_targets() -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    first, _attestor = _authority(now)
    second = first.model_copy(
        update={
            "issuer": "PAJIN second deterministic AI target",
            "target_profile": "kisa-lab-v2",
        }
    )
    registry = TargetAttestationTrustRegistry(
        registry_id="pajin-targets-2026-07",
        entries=[
            TargetAttestationTrustRegistryEntry(
                target="http://ai-target:8080/v1/chat",
                trust_anchor=first,
            ),
            TargetAttestationTrustRegistryEntry(
                target="https://ai.example.test/v1/chat",
                trust_anchor=second,
            ),
        ],
    )

    assert registry.resolve("http://ai-target:8080/v1/chat") == first
    assert registry.resolve("https://ai.example.test/v1/chat") == second
    with pytest.raises(ValueError, match="absent from the exact trust registry"):
        registry.resolve("https://ai.example.test/v1/other")
    assert (
        parse_target_attestation_trust_registry(
            json.dumps(registry.model_dump(mode="json"), separators=(",", ":")).encode()
        )
        == registry
    )
    assert "tls_leaf_spki_sha256" not in registry.model_dump(mode="json")["entries"][1]
    assert len(registry.digest) == 64


def test_target_trust_registry_rejects_unsorted_or_noncanonical_routes() -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    anchor, _attestor = _authority(now)

    with pytest.raises(ValueError, match="uniquely sorted"):
        TargetAttestationTrustRegistry(
            registry_id="pajin-targets-2026-07",
            entries=[
                TargetAttestationTrustRegistryEntry(
                    target="https://z.example.test/v1/chat",
                    trust_anchor=anchor,
                ),
                TargetAttestationTrustRegistryEntry(
                    target="https://a.example.test/v1/chat",
                    trust_anchor=anchor,
                ),
            ],
        )
    with pytest.raises(ValueError, match="canonical exact URL"):
        TargetAttestationTrustRegistryEntry(
            target="https://AI.EXAMPLE.TEST/v1/chat",
            trust_anchor=anchor,
        )


def test_target_trust_registry_v2_requires_exact_https_leaf_spki_pins() -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    anchor, _attestor = _authority(now)
    pinned = TargetAttestationTrustRegistry(
        api_version="pajin.replay.target-attestation-trust-registry/v2",
        registry_id="pajin-targets-2026-07-pinned",
        entries=[
            TargetAttestationTrustRegistryEntry(
                target="https://ai.example.test/v1/chat",
                trust_anchor=anchor,
                tls_leaf_spki_sha256="c" * 64,
            )
        ],
    )

    assert pinned.resolve_entry("https://ai.example.test/v1/chat").tls_leaf_spki_sha256 == (
        "c" * 64
    )
    assert (
        parse_target_attestation_trust_registry(
            json.dumps(pinned.model_dump(mode="json"), separators=(",", ":")).encode()
        )
        == pinned
    )
    with pytest.raises(ValueError, match="v1 cannot carry TLS certificate pins"):
        TargetAttestationTrustRegistry(
            registry_id="pajin-targets-legacy-pinned",
            entries=pinned.entries,
        )
    with pytest.raises(ValueError, match="requires an HTTPS TLS leaf SPKI pin"):
        TargetAttestationTrustRegistry(
            api_version="pajin.replay.target-attestation-trust-registry/v2",
            registry_id="pajin-targets-missing-pin",
            entries=[
                TargetAttestationTrustRegistryEntry(
                    target="https://ai.example.test/v1/chat",
                    trust_anchor=anchor,
                )
            ],
        )
    with pytest.raises(ValueError, match="only for HTTPS routes"):
        TargetAttestationTrustRegistry(
            api_version="pajin.replay.target-attestation-trust-registry/v2",
            registry_id="pajin-targets-http-pin",
            entries=[
                TargetAttestationTrustRegistryEntry(
                    target="http://ai-target:8080/v1/chat",
                    trust_anchor=anchor,
                    tls_leaf_spki_sha256="d" * 64,
                )
            ],
        )


def test_target_trust_registry_v4_requires_https_session_binding() -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    anchor, _attestor = _authority(now)
    entry = TargetAttestationTrustRegistryEntry(
        target="https://ai.example.test/v1/chat",
        trust_anchor=anchor,
        tls_leaf_spki_sha256="c" * 64,
        tls_session_binding="tls-unique-sha256",
    )
    registry = TargetAttestationTrustRegistry(
        api_version="pajin.replay.target-attestation-trust-registry/v4",
        registry_id="pajin-targets-2026-07-session-bound",
        entries=[entry],
    )

    assert registry.resolve_entry(entry.target).tls_session_binding == (
        "tls-unique-sha256"
    )
    with pytest.raises(ValueError, match="v1-v3 cannot carry a TLS session binding"):
        TargetAttestationTrustRegistry(
            api_version="pajin.replay.target-attestation-trust-registry/v3",
            registry_id="pajin-targets-invalid-session-binding",
            entries=[entry],
        )
    with pytest.raises(ValueError, match="v4 requires HTTPS TLS session binding"):
        TargetAttestationTrustRegistry(
            api_version="pajin.replay.target-attestation-trust-registry/v4",
            registry_id="pajin-targets-missing-session-binding",
            entries=[
                entry.model_copy(update={"tls_session_binding": None}),
            ],
        )


def test_signed_registry_bundle_limits_rotation_and_verifies_distribution_signature() -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    distribution_anchor, bundle = _signed_registry_bundle(now)
    entry = bundle.statement.registry.resolve_entry("https://ai.example.test/v1/chat")

    assert verify_target_attestation_registry_bundle(
        bundle,
        trust_anchor=distribution_anchor,
        now=now + timedelta(minutes=30),
    ) == "registry-key-2026-01"
    assert (
        parse_target_attestation_registry_bundle(
            json.dumps(bundle.model_dump(mode="json"), separators=(",", ":")).encode()
        )
        == bundle
    )
    assert entry.accepted_tls_leaf_spki_sha256(now + timedelta(minutes=30)) == frozenset(
        {"c" * 64, "d" * 64}
    )
    assert entry.accepted_tls_leaf_spki_sha256(now + timedelta(hours=1)) == frozenset(
        {"c" * 64}
    )

    changed_statement = bundle.statement.model_copy(
        update={"registry": bundle.statement.registry.model_copy(update={"registry_id": "other"})}
    )
    tampered = bundle.model_copy(
        update={
            "statement": changed_statement,
            "statement_sha256": sha256(
                canonical_target_json(changed_statement.model_dump(mode="json"))
            ).hexdigest(),
        }
    )
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_target_attestation_registry_bundle(
            tampered,
            trust_anchor=distribution_anchor,
            now=now,
        )


def test_signed_registry_bundle_accepts_session_bound_registry_v4() -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    target_anchor, _target_attestor = _authority(now)
    distribution_anchor, signer = _registry_distribution_authority(now)
    registry = TargetAttestationTrustRegistry(
        api_version="pajin.replay.target-attestation-trust-registry/v4",
        registry_id="pajin-targets-session-bound",
        entries=[
            TargetAttestationTrustRegistryEntry(
                target="https://ai.example.test/v1/chat",
                trust_anchor=target_anchor,
                tls_leaf_spki_sha256="c" * 64,
                tls_session_binding="tls-unique-sha256",
            )
        ],
    )

    bundle = signer.sign(
        registry=registry,
        sequence=1,
        previous_bundle_sha256=None,
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(days=1),
    )

    assert verify_target_attestation_registry_bundle(
        bundle,
        trust_anchor=distribution_anchor,
        now=now + timedelta(minutes=1),
    ) == "registry-key-2026-01"


def test_signed_registry_bundle_rejects_unbounded_or_unsigned_v3_rotation() -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    target_anchor, _target_attestor = _authority(now)
    distribution_anchor, signer = _registry_distribution_authority(now)
    registry = TargetAttestationTrustRegistry(
        api_version="pajin.replay.target-attestation-trust-registry/v3",
        registry_id="unbounded-overlap",
        entries=[
            TargetAttestationTrustRegistryEntry(
                target="https://ai.example.test/v1/chat",
                trust_anchor=target_anchor,
                tls_leaf_spki_sha256="c" * 64,
                retiring_tls_leaf_spki_sha256="d" * 64,
                retiring_tls_leaf_spki_not_after=now + timedelta(hours=25),
            )
        ],
    )

    with pytest.raises(ValueError, match="24-hour overlap"):
        signer.sign(
            registry=registry,
            sequence=1,
            previous_bundle_sha256=None,
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(days=2),
        )
    with pytest.raises(ValueError, match="requires a signed distribution bundle"):
        ControlPlaneSettings(
            database_url="sqlite:///:memory:",
            credentials={
                "t" * 32: Principal(
                    subject="registry-test-auditor",
                    roles=frozenset({PrincipalRole.AUDITOR}),
                )
            },
            checkpoint_keys={"v1": b"k" * 32},
            target_attestation_trust_registry=registry,
        )
    assert distribution_anchor.digest


def test_signed_registry_activation_is_monotonic_and_append_only(tmp_path: Path) -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    distribution_anchor, first = _signed_registry_bundle(now)
    repository = ControlPlaneRepository(
        f"sqlite:///{(tmp_path / 'registry-activation.db').as_posix()}"
    )
    repository.initialize()
    try:
        def service_for(bundle: TargetAttestationRegistryBundle) -> ControlPlaneService:
            return ControlPlaneService(
                repository,
                CheckpointSigner(active_key_id="v1", keys={"v1": b"k" * 32}),
                target_attestation_registry_bundle=bundle,
                target_attestation_registry_trust_anchor=distribution_anchor,
            )

        first_service = service_for(first)
        first_service.activate_target_attestation_registry(now=now + timedelta(minutes=1))
        first_service.activate_target_attestation_registry(now=now + timedelta(minutes=1))

        _second_anchor, second = _signed_registry_bundle(
            now + timedelta(minutes=2),
            sequence=2,
            previous_bundle_sha256=first.digest,
            registry_id="pajin-targets-2026-07-rotation",
        )
        second_service = service_for(second)
        second_service.activate_target_attestation_registry(now=now + timedelta(minutes=3))

        with repository.transaction() as session:
            rows = list(
                session.scalars(
                    select(TargetAttestationRegistryVersionRecord).order_by(
                        TargetAttestationRegistryVersionRecord.sequence
                    )
                )
            )
        assert [row.sequence for row in rows] == [1, 2]
        assert rows[1].previous_bundle_digest == first.digest

        with pytest.raises(StateConflict, match="rollback"):
            first_service.activate_target_attestation_registry(now=now + timedelta(minutes=4))

        _other_anchor, equivocated = _signed_registry_bundle(
            now + timedelta(minutes=2),
            sequence=2,
            previous_bundle_sha256=first.digest,
            registry_id="pajin-targets-equivocated",
        )
        with pytest.raises(StateConflict, match="equivocated"):
            service_for(equivocated).activate_target_attestation_registry(
                now=now + timedelta(minutes=4)
            )

        _gap_anchor, gap = _signed_registry_bundle(
            now + timedelta(minutes=4),
            sequence=4,
            previous_bundle_sha256=second.digest,
            registry_id="pajin-targets-gap",
        )
        with pytest.raises(StateConflict, match="gap"):
            service_for(gap).activate_target_attestation_registry(
                now=now + timedelta(minutes=5)
            )

        _wrong_anchor, wrong_predecessor = _signed_registry_bundle(
            now + timedelta(minutes=4),
            sequence=3,
            previous_bundle_sha256="f" * 64,
            registry_id="pajin-targets-wrong-predecessor",
        )
        with pytest.raises(StateConflict, match="predecessor"):
            service_for(wrong_predecessor).activate_target_attestation_registry(
                now=now + timedelta(minutes=5)
            )
    finally:
        repository.close()


def test_control_plane_lifespan_activates_signed_registry_before_serving(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    distribution_anchor, bundle = _signed_registry_bundle(now)
    app = create_app(
        ControlPlaneSettings(
            database_url=f"sqlite:///{(tmp_path / 'lifespan-registry.db').as_posix()}",
            credentials={
                "t" * 32: Principal(
                    subject="registry-lifespan-auditor",
                    roles=frozenset({PrincipalRole.AUDITOR}),
                )
            },
            checkpoint_keys={"v1": b"k" * 32},
            target_attestation_registry_bundle=bundle,
            target_attestation_registry_trust_anchor=distribution_anchor,
        )
    )

    with TestClient(app):
        with app.state.repository.read_transaction() as session:
            activated = session.scalar(select(TargetAttestationRegistryVersionRecord))
            activated_digest = None if activated is None else activated.bundle_digest
        assert activated is not None
        assert activated_digest == bundle.digest


def test_registry_bundle_url_requires_https() -> None:
    with pytest.raises(RuntimeError, match="absolute HTTPS URL"):
        _load_target_attestation_registry_bundle(
            inline=None,
            url="http://registry.example.test/bundle.json",
        )


def test_registry_bundle_https_fetch_is_bounded_and_redirect_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    _distribution_anchor, bundle = _signed_registry_bundle(now)
    content = json.dumps(bundle.model_dump(mode="json"), separators=(",", ":")).encode()
    url = "https://registry.example.test/bundle.json"

    class Response:
        def __init__(self, *, response_url: str, body: bytes) -> None:
            self.response_url = response_url
            self.body = body

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def geturl(self) -> str:
            return self.response_url

        def getcode(self) -> int:
            return 200

        def read(self, limit: int) -> bytes:
            return self.body[:limit]

    class Opener:
        def __init__(self, response: Response) -> None:
            self.response = response

        def open(self, *_args: object, **_kwargs: object) -> Response:
            return self.response

    monkeypatch.setattr(
        control_plane_api,
        "build_opener",
        lambda *_handlers: Opener(Response(response_url=url, body=content)),
    )
    assert _load_target_attestation_registry_bundle(inline=None, url=url) == bundle

    monkeypatch.setattr(
        control_plane_api,
        "build_opener",
        lambda *_handlers: Opener(
            Response(
                response_url="https://other.example.test/bundle.json",
                body=content,
            )
        ),
    )
    with pytest.raises(RuntimeError, match="redirected"):
        _load_target_attestation_registry_bundle(inline=None, url=url)

    monkeypatch.setattr(
        control_plane_api,
        "build_opener",
        lambda *_handlers: Opener(
            Response(
                response_url=url,
                body=b"x" * (512 * 1024 + 1),
            )
        ),
    )
    with pytest.raises(RuntimeError, match="exceeds 512 KiB"):
        _load_target_attestation_registry_bundle(inline=None, url=url)


def test_control_plane_rejects_tls_pin_mismatch_and_v1_binding_downgrade() -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    target = "https://ai.example.test/v1/chat"
    challenge = derive_target_execution_challenge(
        permit_digest="a" * 64,
        replay_request_id=f"tool_replay_{'1' * 32}",
        batch_id=f"replay-batch_{'2' * 32}",
        item_id=f"replay-item_{'3' * 32}",
        ticket_id=f"replay-ticket_{'4' * 32}",
        fencing_value=1,
        call_ordinal=1,
        target=target,
        method="POST",
        compiled_argument_digest="b" * 64,
        issued_at=now,
        expires_at=now + timedelta(seconds=20),
    )
    permit = SimpleNamespace(
        replay_request_id=challenge.replay_request_id,
        target=target,
        method="POST",
    )
    binding_fields = {
        "replay_request_id": challenge.replay_request_id,
        "exchange_ordinal": 1,
        "challenge_sha256": challenge.digest,
        "target_receipt_sha256": "c" * 64,
        "target_sha256": challenge.target_sha256,
        "connect_sequence": 1,
        "connect_authority": "ai.example.test:443",
        "connect_authority_sha256": sha256(b"ai.example.test:443").hexdigest(),
        "connect_address": "203.0.113.10",
        "application_method": "POST",
        "transcript_request_json_sha256": "d" * 64,
        "transcript_response_json_sha256": "e" * 64,
    }
    pinned = TargetExecutionTLSBindingV2(
        **binding_fields,
        tls_peer_leaf_spki_sha256="f" * 64,
    )
    session_bound = TargetExecutionTLSBindingV3(
        **binding_fields,
        tls_peer_leaf_spki_sha256="f" * 64,
        tls_version="TLSv1.2",
        tls_session_binding="tls-unique-sha256",
        tls_session_binding_sha256="0" * 64,
    )
    legacy = TargetExecutionTLSBinding(**binding_fields)
    assert isinstance(
        TypeAdapter(TargetExecutionTransportBinding).validate_python(
            pinned.model_dump(mode="json")
        ),
        TargetExecutionTLSBindingV2,
    )
    assert isinstance(
        TypeAdapter(TargetExecutionTransportBinding).validate_python(
            session_bound.model_dump(mode="json")
        ),
        TargetExecutionTLSBindingV3,
    )

    arguments = {
        "permit": permit,
        "challenge": challenge,
        "exchange_ordinal": 1,
        "receipt_digest": "c" * 64,
        "status": 200,
        "request_digest": "d" * 64,
        "response_digest": "e" * 64,
    }
    assert _target_transport_binding_matches(
        pinned,
        **arguments,
        expected_tls_leaf_spki_sha256="f" * 64,
    )
    assert _target_transport_binding_matches(
        pinned,
        **arguments,
        expected_tls_leaf_spki_sha256=frozenset({"0" * 64, "f" * 64}),
    )
    assert not _target_transport_binding_matches(
        pinned,
        **arguments,
        expected_tls_leaf_spki_sha256="0" * 64,
    )
    assert not _target_transport_binding_matches(
        legacy,
        **arguments,
        expected_tls_leaf_spki_sha256="f" * 64,
    )
    assert _target_transport_binding_matches(
        session_bound,
        **arguments,
        expected_tls_leaf_spki_sha256="f" * 64,
        expected_tls_session_binding="tls-unique-sha256",
        receipt_tls_session_binding_sha256="0" * 64,
    )
    assert not _target_transport_binding_matches(
        pinned,
        **arguments,
        expected_tls_leaf_spki_sha256="f" * 64,
        expected_tls_session_binding="tls-unique-sha256",
        receipt_tls_session_binding_sha256="0" * 64,
    )
    assert not _target_transport_binding_matches(
        session_bound,
        **arguments,
        expected_tls_leaf_spki_sha256="f" * 64,
        expected_tls_session_binding="tls-unique-sha256",
        receipt_tls_session_binding_sha256="1" * 64,
    )

    summary = TargetExecutionVerificationSummary(
        trust_anchor_digest="a" * 64,
        trust_registry_id="pajin-targets-session-bound",
        trust_registry_digest="b" * 64,
        proof_set_digest="c" * 64,
        receipt_count=1,
        receipt_digests=["d" * 64],
        key_ids=["target-key-2026-01"],
        tls_peer_leaf_spki_sha256_digests=["f" * 64],
        tls_session_binding="tls-unique-sha256",
        tls_session_binding_sha256_digests=["0" * 64],
    )
    assert summary.tls_session_binding_sha256_digests == ["0" * 64]
    with pytest.raises(ValueError, match="must be present together"):
        TargetExecutionVerificationSummary.model_validate(
            {
                **summary.model_dump(mode="json"),
                "tls_session_binding": None,
            }
        )


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


def test_control_plane_loads_versioned_target_trust_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    anchor, _attestor = _authority(now)
    registry = TargetAttestationTrustRegistry(
        registry_id="pajin-targets-2026-07",
        entries=[
            TargetAttestationTrustRegistryEntry(
                target="https://ai.example.test/v1/chat",
                trust_anchor=anchor,
            )
        ],
    )
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", "o" * 32)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", "a" * 32)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", "w" * 32)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "checkpoint-key-that-is-at-least-32-bytes",
    )
    monkeypatch.setenv(
        "PAJIN_CP_TARGET_ATTESTATION_TRUST_REGISTRY",
        json.dumps(registry.model_dump(mode="json"), separators=(",", ":")),
    )

    settings = ControlPlaneSettings.from_env()

    assert settings.target_attestation_trust_anchor is None
    assert settings.target_attestation_trust_registry == registry


def test_control_plane_loads_signed_target_registry_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    distribution_anchor, bundle = _signed_registry_bundle(now)
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", "o" * 32)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", "a" * 32)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", "w" * 32)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "checkpoint-key-that-is-at-least-32-bytes",
    )
    monkeypatch.setenv(
        "PAJIN_CP_TARGET_ATTESTATION_REGISTRY_TRUST_ANCHOR",
        json.dumps(distribution_anchor.model_dump(mode="json"), separators=(",", ":")),
    )
    monkeypatch.setenv(
        "PAJIN_CP_TARGET_ATTESTATION_TRUST_REGISTRY_BUNDLE",
        json.dumps(bundle.model_dump(mode="json"), separators=(",", ":")),
    )

    settings = ControlPlaneSettings.from_env()

    assert settings.target_attestation_registry_bundle == bundle
    assert settings.target_attestation_registry_trust_anchor == distribution_anchor
    assert settings.target_attestation_trust_registry is None


def test_control_plane_rejects_ambiguous_target_trust_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 7, 24, 1, 2, 3, tzinfo=UTC)
    anchor, _attestor = _authority(now)
    registry = TargetAttestationTrustRegistry(
        registry_id="pajin-targets-2026-07",
        entries=[
            TargetAttestationTrustRegistryEntry(
                target="https://ai.example.test/v1/chat",
                trust_anchor=anchor,
            )
        ],
    )
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
    monkeypatch.setenv(
        "PAJIN_CP_TARGET_ATTESTATION_TRUST_REGISTRY",
        json.dumps(registry.model_dump(mode="json"), separators=(",", ":")),
    )

    with pytest.raises(RuntimeError, match="mutually exclusive"):
        ControlPlaneSettings.from_env()
