from __future__ import annotations

import ast
import base64
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import pajin.web_assessment.analysis_live_authorization_v2 as authorization_v2_module
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.web_assessment.analysis_compact_live_pins import (
    build_compact_web_analysis_runtime_pin,
    build_compact_web_analysis_transport_pin,
)
from pajin.web_assessment.analysis_live_authorization import (
    VerifiedWebAnalysisOneCallAuthorization,
    WebAnalysisOneCallAuthorizationError,
    WebAnalysisOneCallAuthorizationKeyState,
    WebAnalysisOneCallAuthorizationTrustAnchor,
    WebAnalysisOneCallAuthorizationVerificationKey,
)
from pajin.web_assessment.analysis_live_authorization_v2 import (
    SignedWebAnalysisOneCallAuthorizationV2,
    VerifiedWebAnalysisOneCallAuthorizationV2,
    WebAnalysisOneCallAuthorizationRequestV2,
    WebAnalysisOneCallAuthorizationStatementV2,
    WebAnalysisOneCallAuthorizationVerifierV2,
    authorization_statement_signing_bytes_v2,
    build_web_analysis_one_call_authorization_request_v2,
    build_web_analysis_one_call_authorization_statement_v2,
    parse_signed_web_analysis_one_call_authorization_v2,
    parse_web_analysis_one_call_authorization_request_v2,
)
from tests.test_web_analysis_live_authorization import (
    _signed as _signed_v1,
)
from tests.test_web_analysis_live_authorization import (
    _statement as _statement_v1,
)
from tests.test_web_analysis_live_authorization import (
    authorization_context as _authorization_context_fixture,
)

_NOW = datetime(2026, 9, 23, 9, 0, tzinfo=UTC)
_KEY_ID = "ephemeral-key-v2"
_NONCE = "ephemeral-nonce-v2-0123456789abcdef"


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


@pytest.fixture(scope="module")  # type: ignore[untyped-decorator]
def authorization_v2_context(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    build_context = cast(Any, _authorization_context_fixture).__wrapped__
    context = build_context(tmp_path_factory)
    compact_runtime = build_compact_web_analysis_runtime_pin(
        context.capacity_pin,
        context.live_request,
        context.transport_pin,
    )
    compact_transport = build_compact_web_analysis_transport_pin(
        compact_runtime,
        context.transport_pin,
    )
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    trust_anchor = WebAnalysisOneCallAuthorizationTrustAnchor(
        trustDomain="pajin.web-analysis.live",
        issuer="external-authorizer.invalid",
        keys=(
            WebAnalysisOneCallAuthorizationVerificationKey(
                keyId=_KEY_ID,
                publicKeyBase64url=_base64url(public_key),
                state=WebAnalysisOneCallAuthorizationKeyState.ACTIVE,
                notBefore=_NOW - timedelta(days=1),
                notAfter=_NOW + timedelta(days=1),
            ),
        ),
    )
    request = build_web_analysis_one_call_authorization_request_v2(
        admission=context.admission,
        live_request=context.live_request,
        capacity_pin=context.capacity_pin,
        lineage_transport_pin=context.transport_pin,
        compact_runtime_pin=compact_runtime,
        compact_transport_pin=compact_transport,
    )
    return SimpleNamespace(
        **vars(context),
        compact_runtime=compact_runtime,
        compact_transport=compact_transport,
        private_key=private_key,
        trust_anchor=trust_anchor,
        request=request,
    )


def _statement(
    context: SimpleNamespace,
    *,
    request: WebAnalysisOneCallAuthorizationRequestV2 | None = None,
    nonce: str = _NONCE,
    issued_at: datetime = _NOW,
    not_before: datetime = _NOW,
    expires_at: datetime = _NOW + timedelta(seconds=120),
) -> WebAnalysisOneCallAuthorizationStatementV2:
    return build_web_analysis_one_call_authorization_statement_v2(
        request or context.request,
        trust_domain=context.trust_anchor.trust_domain,
        issuer=context.trust_anchor.issuer,
        signing_key_id=_KEY_ID,
        nonce=nonce,
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
    )


def _signed(
    context: SimpleNamespace,
    statement: WebAnalysisOneCallAuthorizationStatementV2,
) -> SignedWebAnalysisOneCallAuthorizationV2:
    wire = canonical_json_bytes(
        statement.model_dump(mode="json", by_alias=True),
        label="test Web analysis authorization v2 statement",
        max_bytes=768 * 1024,
    )
    return SignedWebAnalysisOneCallAuthorizationV2(
        keyId=_KEY_ID,
        statement=statement,
        statementSha256=sha256(wire).hexdigest(),
        signatureBase64url=_base64url(
            context.private_key.sign(authorization_statement_signing_bytes_v2(statement))
        ),
    )


def _verifier(
    context: SimpleNamespace,
    *,
    clock: datetime = _NOW + timedelta(seconds=30),
) -> WebAnalysisOneCallAuthorizationVerifierV2:
    return WebAnalysisOneCallAuthorizationVerifierV2(
        trust_anchor=context.trust_anchor,
        expected_trust_anchor_digest=context.trust_anchor.digest,
        clock=lambda: clock,
    )


def _verify(
    context: SimpleNamespace,
    bundle: SignedWebAnalysisOneCallAuthorizationV2,
    *,
    clock: datetime = _NOW + timedelta(seconds=30),
) -> Any:
    return _verifier(context, clock=clock).verify(
        bundle,
        admission=context.admission,
        live_request=context.live_request,
        capacity_pin=context.capacity_pin,
        lineage_transport_pin=context.transport_pin,
        compact_runtime_pin=context.compact_runtime,
        compact_transport_pin=context.compact_transport,
    )


def _changed_request(
    context: SimpleNamespace,
    field: str,
    value: object,
) -> WebAnalysisOneCallAuthorizationRequestV2:
    raw = context.request.model_dump(mode="json", by_alias=True)
    raw["requestDigest"] = ""
    raw[field] = value
    return WebAnalysisOneCallAuthorizationRequestV2.model_validate(raw)


def test_v2_authorization_binds_exact_compact_request_and_nonce_coordinate(
    authorization_v2_context: SimpleNamespace,
) -> None:
    context = authorization_v2_context
    bundle = _signed(context, _statement(context))

    verified = _verify(context, bundle)

    assert context.request.live_request_digest == context.live_request.request_digest
    assert context.request.preparation_identity == context.admission.preparation_digest
    assert context.request.provider_chat_request_digest == context.live_request.chat_request_digest
    assert context.request.model_id == context.capacity_pin.model_id
    assert context.request.maximum_completion_tokens == 1024
    assert context.request.compact_runtime_pin_digest == context.compact_runtime.pin_digest
    assert context.request.compact_transport_pin_digest == context.compact_transport.pin_digest
    assert verified.transport_pin_digest == context.compact_transport.pin_digest
    assert verified.lineage_transport_pin_digest == context.transport_pin.pin_digest
    assert verified.compact_runtime_pin_digest == context.compact_runtime.pin_digest
    assert verified.compact_transport_pin_digest == context.compact_transport.pin_digest
    assert verified.api_version.endswith("/v1alpha2")
    assert verified.status == "verified-external-compact-one-call-not-claimed-no-dispatch"
    assert verified.coordinate.authorization_envelope_digest == bundle.digest
    assert verified.coordinate.nonce == _NONCE
    assert verified.dispatch_count == 0
    assert verified.dispatch_ready is False
    assert verified.target_request_authority is False
    assert verified.tool_request_authority is False
    assert verified.finding_authority is False
    assert verified.graph_admission_authority is False
    assert verified.report_authority is False
    assert verified.retry_authority is False


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    ("field", "value"),
    (
        ("preparationIdentity", "1" * 64),
        ("liveRequestDigest", "2" * 64),
        ("providerChatRequestDigest", "3" * 64),
        ("modelId", "different-model"),
        ("lineageTransportPinDigest", "4" * 64),
        ("compactRuntimePinDigest", "5" * 64),
        ("compactTransportPinDigest", "6" * 64),
        ("capacityPinDigest", "7" * 64),
        ("admissionDigest", "8" * 64),
        ("providerRegistrationDigest", "9" * 64),
    ),
)
def test_validly_signed_v2_exact_binding_mismatch_fails_closed(
    authorization_v2_context: SimpleNamespace,
    field: str,
    value: object,
) -> None:
    context = authorization_v2_context
    request = _changed_request(context, field, value)
    bundle = _signed(context, _statement(context, request=request))

    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="exact compact live inputs"):
        _verify(context, bundle)


def test_v2_request_rejects_transport_and_completion_profile_drift(
    authorization_v2_context: SimpleNamespace,
) -> None:
    raw = authorization_v2_context.request.model_dump(mode="json", by_alias=True)
    raw["requestDigest"] = ""
    raw["compactTransportVersion"] = "pajin.web-analysis.provider-transport/v2"
    with pytest.raises(ValidationError):
        WebAnalysisOneCallAuthorizationRequestV2.model_validate(raw)

    raw = authorization_v2_context.request.model_dump(mode="json", by_alias=True)
    raw["requestDigest"] = ""
    raw["maximumCompletionTokens"] = 128
    with pytest.raises(ValidationError):
        WebAnalysisOneCallAuthorizationRequestV2.model_validate(raw)


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    ("clock", "not_before", "expires_at"),
    (
        (_NOW + timedelta(seconds=120), _NOW, _NOW + timedelta(seconds=120)),
        (
            _NOW + timedelta(seconds=30),
            _NOW + timedelta(seconds=31),
            _NOW + timedelta(seconds=120),
        ),
    ),
    ids=("expired", "not-yet-valid"),
)
def test_v2_expired_or_not_yet_valid_bundle_fails_closed(
    authorization_v2_context: SimpleNamespace,
    clock: datetime,
    not_before: datetime,
    expires_at: datetime,
) -> None:
    context = authorization_v2_context
    bundle = _signed(
        context,
        _statement(context, not_before=not_before, expires_at=expires_at),
    )

    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="not currently valid"):
        _verify(context, bundle, clock=clock)


def test_v2_statement_rejects_unbounded_validity_and_bad_nonce(
    authorization_v2_context: SimpleNamespace,
) -> None:
    context = authorization_v2_context
    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="failed closed"):
        _statement(context, expires_at=_NOW + timedelta(seconds=181))
    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="failed closed"):
        _statement(context, nonce="too-short")
    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="failed closed"):
        _statement(context, nonce="contains whitespace 012345")


def test_v2_invalid_signature_fails_closed(
    authorization_v2_context: SimpleNamespace,
) -> None:
    context = authorization_v2_context
    raw = _signed(context, _statement(context)).model_dump(mode="python", by_alias=True)
    raw["signatureBase64url"] = _base64url(b"\x00" * 64)
    forged = SignedWebAnalysisOneCallAuthorizationV2.model_validate(raw)

    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="signature verification"):
        _verify(context, forged)


def test_same_v2_nonce_maps_distinct_envelopes_to_one_durable_identity(
    authorization_v2_context: SimpleNamespace,
) -> None:
    context = authorization_v2_context
    first = _verify(context, _signed(context, _statement(context)))
    second_statement = _statement(
        context,
        issued_at=_NOW + timedelta(seconds=1),
        not_before=_NOW + timedelta(seconds=1),
        expires_at=_NOW + timedelta(seconds=121),
    )
    second = _verify(context, _signed(context, second_statement))

    assert first.authorization_envelope_digest != second.authorization_envelope_digest
    assert first.coordinate.authorization_identity == second.coordinate.authorization_identity


def test_verified_v1_result_cannot_substitute_for_verified_v2(
    authorization_v2_context: SimpleNamespace,
) -> None:
    context = authorization_v2_context
    verified_v2 = _verify(context, _signed(context, _statement(context)))
    legacy_raw = verified_v2.model_dump(mode="python", by_alias=True)
    for field in (
        "lineageTransportPinDigest",
        "compactRuntimePinDigest",
        "compactTransportPinDigest",
        "compactRuntimeBound",
        "compactTransportBound",
    ):
        legacy_raw.pop(field)
    legacy_raw.update(
        {
            "apiVersion": "pajin.dev/verified-web-analysis-one-call-authorization/v1alpha1",
            "kind": "VerifiedWebAnalysisOneCallAuthorization",
            "verificationId": "",
            "verificationDigest": "",
            "status": "verified-external-one-call-not-claimed-no-dispatch",
        }
    )
    legacy = VerifiedWebAnalysisOneCallAuthorization.model_validate(legacy_raw)

    with pytest.raises(ValidationError):
        VerifiedWebAnalysisOneCallAuthorizationV2.model_validate(
            legacy.model_dump(mode="python", by_alias=True)
        )


def test_actual_signed_v1_bundle_cannot_enter_v2_parser(
    authorization_v2_context: SimpleNamespace,
) -> None:
    legacy = _signed_v1(_statement_v1(authorization_v2_context))
    wire = canonical_json_bytes(
        legacy.model_dump(mode="json", by_alias=True),
        label="actual signed v1 authorization bundle",
    )

    with pytest.raises(WebAnalysisOneCallAuthorizationError):
        parse_signed_web_analysis_one_call_authorization_v2(wire + b"\n")


def test_v2_strict_parsers_require_canonical_json_plus_one_lf(
    authorization_v2_context: SimpleNamespace,
) -> None:
    context = authorization_v2_context
    bundle = _signed(context, _statement(context))
    request_canonical = canonical_json_bytes(
        context.request.model_dump(mode="json", by_alias=True),
        label="test canonical v2 authorization request",
    )
    bundle_canonical = canonical_json_bytes(
        bundle.model_dump(mode="json", by_alias=True),
        label="test canonical v2 authorization bundle",
    )
    assert (
        parse_web_analysis_one_call_authorization_request_v2(request_canonical + b"\n")
        == context.request
    )
    assert parse_signed_web_analysis_one_call_authorization_v2(bundle_canonical + b"\n") == bundle
    with pytest.raises(WebAnalysisOneCallAuthorizationError):
        parse_web_analysis_one_call_authorization_request_v2(b'{"x":1,"x":2}')
    raw = bundle.model_dump(mode="json", by_alias=True)
    raw["campaignApproval"] = {"approved": True}
    with pytest.raises(WebAnalysisOneCallAuthorizationError):
        parse_signed_web_analysis_one_call_authorization_v2(
            canonical_json_bytes(raw, label="authorization v2 with unknown authority") + b"\n"
        )
    pretty_request = json.dumps(
        context.request.model_dump(mode="json", by_alias=True),
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    for invalid in (
        request_canonical,
        request_canonical + b"\n\n",
        pretty_request + b"\n",
    ):
        with pytest.raises(WebAnalysisOneCallAuthorizationError):
            parse_web_analysis_one_call_authorization_request_v2(invalid)
    pretty_bundle = json.dumps(
        bundle.model_dump(mode="json", by_alias=True),
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    for invalid in (
        bundle_canonical,
        bundle_canonical + b"\n\n",
        pretty_bundle + b"\n",
    ):
        with pytest.raises(WebAnalysisOneCallAuthorizationError):
            parse_signed_web_analysis_one_call_authorization_v2(invalid)


def test_v2_verifier_rechecks_independent_trust_anchor_digest(
    authorization_v2_context: SimpleNamespace,
) -> None:
    context = authorization_v2_context
    verifier = _verifier(context)
    object.__setattr__(
        verifier,
        "trust_anchor",
        context.trust_anchor.model_copy(update={"issuer": "drift.invalid"}),
    )

    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="drifted"):
        verifier.verify(
            _signed(context, _statement(context)),
            admission=context.admission,
            live_request=context.live_request,
            capacity_pin=context.capacity_pin,
            lineage_transport_pin=context.transport_pin,
            compact_runtime_pin=context.compact_runtime,
            compact_transport_pin=context.compact_transport,
        )


def test_production_v2_verifier_has_no_signer_or_execution_imports() -> None:
    source_path = Path(authorization_v2_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    forbidden = {
        "subprocess",
        "pajin.benchmark.effectiveness.docker",
        "pajin.graph.approval",
        "pajin.providers.session",
        "pajin.runtime.secrets",
        "pajin.runtime.worker",
        "pajin.web_assessment.analysis_local",
        "pajin.web_assessment.analysis_skill_runtime",
    }
    assert imported_modules.isdisjoint(forbidden)
    assert "Ed25519PrivateKey" not in source
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"sign", "issue", "approve"}
        for node in ast.walk(tree)
    )
