from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.identity import (
    OIDCHumanAuthenticator,
    OIDCHumanIdentityMapping,
    OIDCHumanTrustPolicy,
    OIDCVerificationKey,
    OIDCVerificationKeyState,
)
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.control_plane.security import (
    AuthenticationError,
    ChainedAuthenticator,
    TokenAuthenticator,
)

NOW = datetime(2026, 8, 12, 0, 0, tzinfo=UTC)
ISSUER = "https://identity.example.invalid/tenant"
AUDIENCE = "https://control-plane.example.invalid"
CLIENT_ID = "pajin-console"
SCOPE = "pajin.control-plane"
ACR = "urn:pajin:authentication:mfa"
KEY_ID = "oidc-key-2026-08"
WORKER_TOKEN = "identity-worker-token-that-is-long-and-distinct"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


@pytest.fixture(scope="module")
def private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65_537, key_size=2_048)


def _spki(key: rsa.RSAPrivateKey) -> str:
    return _b64(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _identity(subject: str, principal: str, *roles: PrincipalRole) -> OIDCHumanIdentityMapping:
    return OIDCHumanIdentityMapping(
        provider_subject=subject,
        principal_subject=principal,
        roles=frozenset(roles),
    )


def _policy(
    key: rsa.RSAPrivateKey,
    *,
    state: OIDCVerificationKeyState = OIDCVerificationKeyState.ACTIVE,
    identities: tuple[OIDCHumanIdentityMapping, ...] | None = None,
) -> OIDCHumanTrustPolicy:
    return OIDCHumanTrustPolicy(
        policy_id="oidc-human-policy_0123456789abcdef0123456789abcdef",
        issuer=ISSUER,
        audience=AUDIENCE,
        client_id=CLIENT_ID,
        required_scope=SCOPE,
        required_acr=ACR,
        required_amr=frozenset({"pwd", "otp"}),
        maximum_token_lifetime_seconds=300,
        maximum_authentication_age_seconds=600,
        clock_skew_seconds=30,
        keys=(
            OIDCVerificationKey(
                key_id=KEY_ID,
                public_key_spki_base64url=_spki(key),
                state=state,
                not_before=NOW - timedelta(days=1),
                not_after=(
                    NOW + timedelta(days=1)
                    if state is not OIDCVerificationKeyState.ACTIVE
                    else None
                ),
                revoked_at=(
                    NOW - timedelta(minutes=1)
                    if state is OIDCVerificationKeyState.REVOKED
                    else None
                ),
            ),
        ),
        identities=identities
        or (
            _identity(
                "provider-alice",
                "oidc:alice@example.com",
                PrincipalRole.OPERATOR,
                PrincipalRole.AUDITOR,
            ),
        ),
    )


def _claims(
    subject: str = "provider-alice",
    *,
    now: datetime = NOW,
) -> dict[str, Any]:
    issued_at = int(now.timestamp())
    return {
        "iss": ISSUER,
        "sub": subject,
        "aud": AUDIENCE,
        "exp": issued_at + 300,
        "iat": issued_at,
        "jti": f"token-{subject}",
        "client_id": CLIENT_ID,
        "scope": f"openid {SCOPE}",
        "auth_time": issued_at - 60,
        "acr": ACR,
        "amr": ["pwd", "otp"],
        "roles": ["approver"],
    }


def _token(
    key: rsa.RSAPrivateKey,
    *,
    claims: dict[str, Any] | None = None,
    header: dict[str, Any] | None = None,
    raw_header: bytes | None = None,
    raw_claims: bytes | None = None,
) -> str:
    header_segment = _b64(
        raw_header
        or json.dumps(
            header or {"alg": "RS256", "kid": KEY_ID, "typ": "at+jwt"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    claims_segment = _b64(
        raw_claims
        or json.dumps(claims or _claims(), sort_keys=True, separators=(",", ":")).encode()
    )
    signing_input = f"{header_segment}.{claims_segment}".encode("ascii")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode()}.{_b64(signature)}"


def _authenticator(key: rsa.RSAPrivateKey) -> OIDCHumanAuthenticator:
    return OIDCHumanAuthenticator(_policy(key), clock=lambda: NOW)


def _rejected(authenticator: OIDCHumanAuthenticator, token: str) -> None:
    with pytest.raises(AuthenticationError, match="invalid bearer credential"):
        authenticator.authenticate(token)


@pytest.mark.parametrize("typ", ["at+jwt", "application/at+jwt", "at+JWT"])
def test_oidc_mfa_access_token_maps_deployment_roles_not_token_roles(
    private_key: rsa.RSAPrivateKey,
    typ: str,
) -> None:
    principal = _authenticator(private_key).authenticate(
        _token(private_key, header={"alg": "RS256", "kid": KEY_ID, "typ": typ})
    )

    assert principal == Principal(
        subject="oidc:alice@example.com",
        roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
    )
    assert PrincipalRole.APPROVER not in principal.roles


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("iss", "https://other.example.invalid"),
        ("aud", "https://other.example.invalid"),
        ("aud", [AUDIENCE, "https://other.example.invalid"]),
        ("client_id", "other-client"),
        ("scope", "openid"),
        ("acr", "single-factor"),
        ("amr", ["pwd"]),
        ("sub", "provider-unknown"),
        ("exp", int((NOW - timedelta(minutes=1)).timestamp())),
        ("iat", int((NOW + timedelta(minutes=1)).timestamp())),
        ("nbf", int((NOW + timedelta(minutes=1)).timestamp())),
        ("auth_time", int((NOW - timedelta(minutes=11)).timestamp())),
        ("jti", "bad token id"),
    ],
)
def test_oidc_rejects_wrong_identity_time_and_mfa_binding(
    private_key: rsa.RSAPrivateKey,
    claim: str,
    value: object,
) -> None:
    claims = _claims()
    claims[claim] = value
    _rejected(_authenticator(private_key), _token(private_key, claims=claims))


@pytest.mark.parametrize("typ", ["JWT", "id+jwt", "application/id+jwt"])
def test_oidc_rejects_id_token_and_untyped_jwt(
    private_key: rsa.RSAPrivateKey,
    typ: str,
) -> None:
    _rejected(
        _authenticator(private_key),
        _token(private_key, header={"alg": "RS256", "kid": KEY_ID, "typ": typ}),
    )


def test_oidc_rejects_algorithm_key_signature_and_revocation(
    private_key: rsa.RSAPrivateKey,
) -> None:
    authenticator = _authenticator(private_key)
    wrong_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)

    _rejected(
        authenticator,
        _token(private_key, header={"alg": "none", "kid": KEY_ID, "typ": "at+jwt"}),
    )
    _rejected(
        authenticator,
        _token(
            private_key,
            header={"alg": "RS256", "kid": "unknown-key", "typ": "at+jwt"},
        ),
    )
    _rejected(authenticator, _token(wrong_key))
    _rejected(
        OIDCHumanAuthenticator(
            _policy(private_key, state=OIDCVerificationKeyState.REVOKED),
            clock=lambda: NOW,
        ),
        _token(private_key),
    )


def test_oidc_rejects_duplicate_header_and_claim_members(
    private_key: rsa.RSAPrivateKey,
) -> None:
    duplicate_header = b'{"alg":"RS256","kid":"oidc-key-2026-08","typ":"at+jwt","alg":"none"}'
    duplicate_claims = (
        json.dumps(_claims(), separators=(",", ":"))[:-1] + ',"sub":"provider-unknown"}'
    ).encode()

    _rejected(_authenticator(private_key), _token(private_key, raw_header=duplicate_header))
    _rejected(_authenticator(private_key), _token(private_key, raw_claims=duplicate_claims))


def test_oidc_policy_rejects_weak_key_and_unsafe_human_authority(
    private_key: rsa.RSAPrivateKey,
) -> None:
    weak_key = rsa.generate_private_key(public_exponent=65_537, key_size=1_024)
    with pytest.raises(ValueError, match="at least 2048 bits"):
        OIDCVerificationKey(
            key_id=KEY_ID,
            public_key_spki_base64url=_spki(weak_key),
            state=OIDCVerificationKeyState.ACTIVE,
            not_before=NOW,
        )
    with pytest.raises(ValueError, match="Worker authority"):
        _identity("provider-worker", "oidc:worker", PrincipalRole.WORKER)
    with pytest.raises(ValueError, match="operator and approver"):
        _identity(
            "provider-admin",
            "oidc:admin",
            PrincipalRole.OPERATOR,
            PrincipalRole.APPROVER,
        )


def test_chained_authenticator_rejects_two_authorities_accepting_one_token(
    private_key: rsa.RSAPrivateKey,
) -> None:
    token = _token(private_key)
    chained = ChainedAuthenticator(
        (
            TokenAuthenticator(
                {
                    token: Principal(
                        subject="legacy-operator",
                        roles=frozenset({PrincipalRole.OPERATOR}),
                    )
                }
            ),
            _authenticator(private_key),
        )
    )

    with pytest.raises(AuthenticationError, match="invalid bearer credential"):
        chained.authenticate(token)


def test_settings_reject_oidc_and_opaque_authority_for_same_subject(
    tmp_path: Path,
    private_key: rsa.RSAPrivateKey,
) -> None:
    with pytest.raises(ValueError, match="must not share a principal subject"):
        ControlPlaneSettings(
            database_url=f"sqlite:///{(tmp_path / 'overlap.db').as_posix()}",
            credentials={
                WORKER_TOKEN: Principal(
                    subject="worker-service",
                    roles=frozenset({PrincipalRole.WORKER}),
                ),
                "opaque-operator-token-that-is-long-and-distinct": Principal(
                    subject="oidc:alice@example.com",
                    roles=frozenset({PrincipalRole.OPERATOR}),
                ),
            },
            checkpoint_keys={"test-v1": b"test-checkpoint-signing-key-32-bytes-minimum"},
            oidc_human_trust_policy=_policy(private_key),
        )


def _complete_policy(key: rsa.RSAPrivateKey) -> OIDCHumanTrustPolicy:
    return _policy(
        key,
        identities=(
            _identity(
                "provider-alice",
                "oidc:alice@example.com",
                PrincipalRole.OPERATOR,
                PrincipalRole.AUDITOR,
            ),
            _identity(
                "provider-bob",
                "oidc:bob@example.com",
                PrincipalRole.APPROVER,
                PrincipalRole.AUDITOR,
            ),
        ),
    )


def test_oidc_actor_is_audited_and_static_worker_token_remains_valid(
    tmp_path: Path,
    private_key: rsa.RSAPrivateKey,
) -> None:
    settings = ControlPlaneSettings(
        database_url=f"sqlite:///{(tmp_path / 'oidc-api.db').as_posix()}",
        credentials={
            WORKER_TOKEN: Principal(
                subject="worker-service",
                roles=frozenset({PrincipalRole.WORKER}),
            )
        },
        checkpoint_keys={"test-v1": b"test-checkpoint-signing-key-32-bytes-minimum"},
        active_checkpoint_key_id="test-v1",
        oidc_human_trust_policy=_complete_policy(private_key),
    )
    request_time = datetime.now(UTC)
    operator_token = _token(private_key, claims=_claims(now=request_time))
    approver_token = _token(
        private_key,
        claims=_claims("provider-bob", now=request_time),
    )

    with TestClient(create_app(settings)) as client:
        submitted = client.post(
            "/v1/runs",
            headers={"Authorization": f"Bearer {operator_token}"},
            json={
                "campaign_name": "oidc-control-plane",
                "idempotency_key": "oidc-audit-actor",
            },
        )
        assert submitted.status_code == 200, submitted.text
        run_id = submitted.json()["run"]["run_id"]
        events = client.get(
            f"/v1/runs/{run_id}/events",
            headers={"Authorization": f"Bearer {approver_token}"},
        )
        worker_claim = client.post(
            "/v1/worker/jobs/claim",
            headers={"Authorization": f"Bearer {WORKER_TOKEN}"},
            json={"worker_id": "worker-1", "kinds": ["tool-loop"], "lease_seconds": 30},
        )
        unknown = client.get(
            f"/v1/runs/{run_id}",
            headers={
                "Authorization": (
                    "Bearer "
                    + _token(
                        private_key,
                        claims=_claims("provider-unknown", now=request_time),
                    )
                )
            },
        )

    assert events.status_code == 200, events.text
    assert any(
        event["event_type"] == "run.submitted" and event["actor"] == "oidc:alice@example.com"
        for event in events.json()
    )
    assert worker_claim.status_code == 204
    assert unknown.status_code == 401


def test_environment_allows_oidc_to_replace_static_human_tokens(
    monkeypatch: pytest.MonkeyPatch,
    private_key: rsa.RSAPrivateKey,
) -> None:
    monkeypatch.delenv("PAJIN_CP_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("PAJIN_CP_APPROVER_TOKEN", raising=False)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "test-checkpoint-signing-key-32-bytes-minimum",
    )
    policy = _complete_policy(private_key)
    monkeypatch.setenv("PAJIN_CP_OIDC_HUMAN_TRUST_POLICY", policy.model_dump_json())

    settings = ControlPlaneSettings.from_env()

    assert set(settings.credentials) == {WORKER_TOKEN}
    assert settings.oidc_human_trust_policy == policy
