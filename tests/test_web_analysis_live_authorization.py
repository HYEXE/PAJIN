from __future__ import annotations

import ast
import asyncio
import base64
import subprocess
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import pajin.web_assessment.analysis_live_authorization as authorization_module
from pajin.agentic.durable import AgenticCoordinationStore
from pajin.benchmark.effectiveness.docker import LocalModelRuntime
from pajin.benchmark.effectiveness.suite import PLATFORM_MANIFESTS, RuntimePin, model_pins
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.graph.approval import ActionApprovalEnvelope
from pajin.providers.session import PolicyBoundProviderPort
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.worker import DockerWorkerBackend
from pajin.supervision.invocation_journal import SupervisorInvocationJournal
from pajin.web_assessment.analysis_capacity import (
    SubprocessLlamaCppTokenizerBackend,
    _conservative_campaign_prompt_bound,
)
from pajin.web_assessment.analysis_capacity_v2 import (
    SubprocessLlamaCppLiveMaterialization,
    _create_web_analysis_capacity_v2_run_with_backend,
    build_web_analysis_capacity_v2_pin,
)
from pajin.web_assessment.analysis_live_authorization import (
    SignedWebAnalysisOneCallAuthorization,
    WebAnalysisOneCallAuthorizationError,
    WebAnalysisOneCallAuthorizationKeyState,
    WebAnalysisOneCallAuthorizationStatement,
    WebAnalysisOneCallAuthorizationTrustAnchor,
    WebAnalysisOneCallAuthorizationVerificationKey,
    WebAnalysisOneCallAuthorizationVerifier,
    parse_signed_web_analysis_one_call_authorization,
    parse_web_analysis_one_call_authorization_trust_anchor,
)
from pajin.web_assessment.analysis_live_claim_journal import (
    WebAnalysisLiveClaimJournal,
    WebAnalysisLiveClaimJournalError,
    WebAnalysisLiveClaimPhase,
    build_web_analysis_live_claim_binding,
)
from pajin.web_assessment.analysis_skill_compact import (
    build_compact_skill_bound_web_analysis_chat_request,
    build_compact_skill_bound_web_analysis_projection,
)
from pajin.web_assessment.analysis_skill_live_invocation import (
    plan_prepared_compact_skill_bound_web_analysis_admission,
    verify_planned_prepared_compact_skill_bound_web_analysis_admission,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    create_compact_skill_bound_web_analysis_preparation_run,
)
from pajin.web_assessment.analysis_skill_projection import (
    create_web_analysis_skill_projection_run,
)
from pajin.web_assessment.analysis_skill_runtime import (
    SkillBoundWebAnalysisInvocationRuntime,
)
from pajin.web_assessment.analysis_transport import web_analysis_transport_runtime_pin
from pajin.web_assessment.discovery_artifact import load_verified_authenticated_discovery
from pajin.web_assessment.models import LocalWebAssessmentAuthorization
from tests.test_web_analysis_capacity_v2 import _FakeV2Tokenizer
from tests.test_web_analysis_skill_live_invocation import (
    _admission_anchors,
    _capacity_anchors,
)
from tests.test_web_discovery_artifact import _run_fake

_SIGNATURE_DOMAIN = b"pajin.web-analysis.one-call-authorization-statement/v1\0"
_NOW = datetime(2026, 9, 22, 9, 0, tzinfo=UTC)
_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
_SECOND_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
_AUTHORITY_FALSE_ALIASES = (
    "targetRequestAuthority",
    "toolRequestAuthority",
    "capabilityAuthority",
    "permitAuthority",
    "findingAuthority",
    "graphAdmissionAuthority",
    "reportAuthority",
    "deliveryAuthority",
    "retryAuthority",
    "scopeExpansionAuthority",
    "generalExecutionAuthority",
    "automaticRedispatchAuthority",
    "campaignApprovalReinterpreted",
)


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _trust_anchor(
    *,
    issuer: str = "external-authorizer.invalid",
) -> WebAnalysisOneCallAuthorizationTrustAnchor:
    public_key = _PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return WebAnalysisOneCallAuthorizationTrustAnchor(
        trustDomain="pajin.web-analysis.live",
        issuer=issuer,
        keys=(
            WebAnalysisOneCallAuthorizationVerificationKey(
                keyId="external-key-v1",
                publicKeyBase64url=_base64url(public_key),
                state=WebAnalysisOneCallAuthorizationKeyState.ACTIVE,
                notBefore=_NOW - timedelta(days=1),
                notAfter=_NOW + timedelta(days=1),
            ),
        ),
    )


def _inactive_signing_anchor(
    state: WebAnalysisOneCallAuthorizationKeyState,
) -> WebAnalysisOneCallAuthorizationTrustAnchor:
    active_public_key = _SECOND_PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signing_public_key = _PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return WebAnalysisOneCallAuthorizationTrustAnchor(
        trustDomain="pajin.web-analysis.live",
        issuer="external-authorizer.invalid",
        keys=(
            WebAnalysisOneCallAuthorizationVerificationKey(
                keyId="active-key-v2",
                publicKeyBase64url=_base64url(active_public_key),
                state=WebAnalysisOneCallAuthorizationKeyState.ACTIVE,
                notBefore=_NOW - timedelta(days=1),
                notAfter=_NOW + timedelta(days=1),
            ),
            WebAnalysisOneCallAuthorizationVerificationKey(
                keyId="external-key-v1",
                publicKeyBase64url=_base64url(signing_public_key),
                state=state,
                notBefore=_NOW - timedelta(days=1),
                notAfter=_NOW + timedelta(days=1),
                revokedAt=(
                    _NOW - timedelta(hours=1)
                    if state is WebAnalysisOneCallAuthorizationKeyState.REVOKED
                    else None
                ),
            ),
        ),
    )


def _plan(source: Any, skill_run: Any, capacity: Any, preparation: Any) -> Any:
    anchors = _admission_anchors(source, skill_run, capacity, preparation)
    planned = plan_prepared_compact_skill_bound_web_analysis_admission(
        source=source,
        skill_run=skill_run,
        capacity_run=capacity,
        preparation_run=preparation,
        **anchors,
    )
    return verify_planned_prepared_compact_skill_bound_web_analysis_admission(
        planned,
        source=source,
        skill_run=skill_run,
        capacity_run=capacity,
        preparation_run=preparation,
        **anchors,
    )


@pytest.fixture(scope="module")
def authorization_context(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    root = tmp_path_factory.mktemp("web-analysis-live-authorization")
    with patch("tests.test_web_discovery_artifact._ORIGIN", "http://127.0.0.1:3000"):
        source_artifacts = asyncio.run(_run_fake(root / "source"))
    source = load_verified_authenticated_discovery(
        source_artifacts.run_path,
        expected_run_id=source_artifacts.index.run_id,
        expected_root_digest=source_artifacts.root_digest,
    )
    skill_run = create_web_analysis_skill_projection_run(
        source=source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        output_root=root / "skill",
    )
    projection = build_compact_skill_bound_web_analysis_projection(skill_run.snapshot)
    chat_request = build_compact_skill_bound_web_analysis_chat_request(skill_run.snapshot)
    base_worker_image = "sha256:" + "1" * 64
    base_proxy_image = "sha256:" + "2" * 64
    worker_image = "sha256:" + "3" * 64
    proxy_image = "sha256:" + "4" * 64
    runtime = RuntimePin(
        platform="linux/arm64",
        platform_manifest=PLATFORM_MANIFESTS["linux/arm64"],
        worker_image=base_worker_image,
        proxy_image=base_proxy_image,
    )
    transport_pin = web_analysis_transport_runtime_pin(
        runtime,
        worker_image=worker_image,
        proxy_image=proxy_image,
    )
    model_pin = model_pins()[0]
    capacity_pin = build_web_analysis_capacity_v2_pin(
        skill_run,
        projection,
        chat_request,
        runtime=runtime,
        model_pin=model_pin,
        transport_pin_digest=transport_pin.pin_digest,
        conservative_campaign_prompt_tokens=_conservative_campaign_prompt_bound(
            chat_request,
            model_id=model_pin.name,
        ),
    )
    capacity = _create_web_analysis_capacity_v2_run_with_backend(
        root / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=chat_request,
        pin=capacity_pin,
        tokenizer_backend=_FakeV2Tokenizer(),
    )
    preparation = create_compact_skill_bound_web_analysis_preparation_run(
        root / "preparation",
        skill_run=skill_run,
        capacity_run=capacity,
        **_capacity_anchors(skill_run, capacity),
    )
    planned = _plan(source, skill_run, capacity, preparation)
    return SimpleNamespace(
        root=root,
        source=source,
        skill_run=skill_run,
        capacity=capacity,
        preparation=preparation,
        admission=planned.admission,
        live_request=preparation.live_request,
        capacity_pin=capacity.pin,
        transport_pin=transport_pin,
    )


def _statement_data(
    context: SimpleNamespace,
    *,
    nonce: str = "one-call-nonce-0123456789abcdef",
    issued_at: datetime = _NOW,
    not_before: datetime = _NOW,
    expires_at: datetime = _NOW + timedelta(seconds=120),
) -> dict[str, object]:
    admission = context.admission
    request = context.live_request
    capacity = context.capacity_pin
    transport = context.transport_pin
    registration = request.provider_registration
    return {
        "trustDomain": "pajin.web-analysis.live",
        "issuer": "external-authorizer.invalid",
        "signingKeyId": "external-key-v1",
        "nonce": nonce,
        "admissionId": admission.admission_id,
        "admissionDigest": admission.admission_digest,
        "preparationRunId": admission.preparation_run_id,
        "preparationRunRootDigest": admission.preparation_run_root_digest,
        "preparationIdentity": admission.preparation_digest,
        "preparationIndexDigest": admission.preparation_index_digest,
        "liveRequestDigest": request.request_digest,
        "providerId": registration.provider_id,
        "modelId": registration.model,
        "providerRegistrationDigest": request.provider_registration_digest,
        "providerChatRequestDigest": request.chat_request_digest,
        "compactProjectionDigest": request.compact_projection_digest,
        "responseSchemaDigest": admission.response_schema_digest,
        "capacityPinDigest": capacity.pin_digest,
        "modelPinDigest": capacity.model_pin_digest,
        "modelSha256": capacity.model_sha256,
        "modelSizeBytes": capacity.model_size_bytes,
        "modelImage": capacity.model_image,
        "modelPlatformManifest": capacity.model_platform_manifest,
        "transportPinDigest": transport.pin_digest,
        "transportVersion": transport.transport_version,
        "workerAction": transport.worker_action,
        "workerImage": transport.worker_image,
        "proxyImage": transport.proxy_image,
        "issuedAt": issued_at,
        "notBefore": not_before,
        "expiresAt": expires_at,
        "attempt": 1,
        "maximumDispatchCount": 1,
        "oneModelCompletionGrantCount": 1,
        "toolsAllowed": False,
        "streamingAllowed": False,
        "targetRequestAuthority": False,
        "toolRequestAuthority": False,
        "capabilityAuthority": False,
        "permitAuthority": False,
        "findingAuthority": False,
        "graphAdmissionAuthority": False,
        "reportAuthority": False,
        "deliveryAuthority": False,
        "retryAuthority": False,
        "scopeExpansionAuthority": False,
        "generalExecutionAuthority": False,
        "automaticRedispatchAuthority": False,
        "campaignApprovalReinterpreted": False,
    }


def _statement(
    context: SimpleNamespace,
    **overrides: object,
) -> WebAnalysisOneCallAuthorizationStatement:
    data = _statement_data(context)
    data.update(overrides)
    return WebAnalysisOneCallAuthorizationStatement.model_validate(data)


def _signed(
    statement: WebAnalysisOneCallAuthorizationStatement,
    *,
    key_id: str = "external-key-v1",
    private_key: Ed25519PrivateKey = _PRIVATE_KEY,
) -> SignedWebAnalysisOneCallAuthorization:
    wire = canonical_json_bytes(
        statement.model_dump(mode="json", by_alias=True),
        label="test Web analysis authorization statement",
        max_bytes=512 * 1024,
    )
    return SignedWebAnalysisOneCallAuthorization(
        keyId=key_id,
        statement=statement,
        statementSha256=sha256(wire).hexdigest(),
        signatureBase64url=_base64url(private_key.sign(_SIGNATURE_DOMAIN + wire)),
    )


def _verifier(
    *,
    clock: datetime = _NOW + timedelta(seconds=30),
    anchor: WebAnalysisOneCallAuthorizationTrustAnchor | None = None,
) -> WebAnalysisOneCallAuthorizationVerifier:
    trust_anchor = anchor or _trust_anchor()
    return WebAnalysisOneCallAuthorizationVerifier(
        trust_anchor=trust_anchor,
        expected_trust_anchor_digest=trust_anchor.digest,
        clock=lambda: clock,
    )


def _verify(
    context: SimpleNamespace,
    authorization: SignedWebAnalysisOneCallAuthorization,
    *,
    verifier: WebAnalysisOneCallAuthorizationVerifier | None = None,
) -> Any:
    return (verifier or _verifier()).verify(
        authorization,
        admission=context.admission,
        live_request=context.live_request,
        capacity_pin=context.capacity_pin,
        transport_pin=context.transport_pin,
    )


def _tree_snapshot(root: Path) -> tuple[tuple[str, int, int], ...]:
    return tuple(
        sorted(
            (str(path.relative_to(root)), path.stat().st_size, path.stat().st_mtime_ns)
            for path in root.rglob("*")
            if path.is_file()
        )
    )


def _patch_no_dispatch_spies(monkeypatch: pytest.MonkeyPatch) -> dict[str, Mock]:
    targets: dict[str, tuple[object, str]] = {
        "live-materialization": (SubprocessLlamaCppLiveMaterialization, "materialize"),
        "tokenizer-start": (SubprocessLlamaCppTokenizerBackend, "start"),
        "provider-chat": (PolicyBoundProviderPort, "chat_bound"),
        "secret-materialize": (SecretBroker, "materialize"),
        "skill-runtime": (SkillBoundWebAnalysisInvocationRuntime, "invoke"),
        "worker-runtime": (DockerWorkerBackend, "__init__"),
        "legacy-local-model": (LocalModelRuntime, "start"),
        "legacy-journal": (SupervisorInvocationJournal, "__init__"),
        "legacy-cas": (AgenticCoordinationStore, "__init__"),
        "live-journal": (WebAnalysisLiveClaimJournal, "__init__"),
        "subprocess": (subprocess, "run"),
    }
    spies: dict[str, Mock] = {}
    for label, (owner, attribute) in targets.items():
        spy = Mock(side_effect=AssertionError(f"authorization verifier crossed {label}"))
        monkeypatch.setattr(owner, attribute, spy)
        spies[label] = spy
    return spies


def test_valid_external_authorization_binds_one_call_without_dispatch(
    authorization_context: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _signed(_statement(authorization_context))
    spies = _patch_no_dispatch_spies(monkeypatch)
    before = _tree_snapshot(authorization_context.root)

    verified = _verify(authorization_context, bundle)

    assert verified.authorization_verified is True
    assert verified.external_one_model_completion_grant_verified is True
    assert verified.one_model_completion_grant_count == 1
    assert verified.authorization_consumed is False
    assert verified.durable_claim_present is False
    assert verified.dispatch_ready is False
    assert verified.dispatch_count == 0
    assert verified.admission_digest == authorization_context.admission.admission_digest
    assert verified.preparation_identity == authorization_context.admission.preparation_digest
    assert verified.live_request_digest == authorization_context.live_request.request_digest
    assert verified.model_id == authorization_context.capacity_pin.model_id
    assert verified.transport_pin_digest == authorization_context.transport_pin.pin_digest
    assert verified.coordinate.authorization_envelope_digest == bundle.digest
    assert verified.coordinate.nonce == bundle.statement.nonce
    assert all(
        getattr(verified, alias) is False
        for alias in (
            "provider_dispatch_authority",
            "target_request_authority",
            "tool_request_authority",
            "capability_authority",
            "permit_authority",
            "finding_authority",
            "graph_admission_authority",
            "report_authority",
            "delivery_authority",
            "retry_authority",
            "scope_expansion_authority",
            "general_execution_authority",
            "automatic_redispatch_authority",
            "campaign_approval_reinterpreted",
        )
    )
    assert _tree_snapshot(authorization_context.root) == before
    for spy in spies.values():
        spy.assert_not_called()


@pytest.mark.parametrize(
    ("clock", "overrides"),
    (
        (
            _NOW + timedelta(seconds=120),
            {},
        ),
        (
            _NOW + timedelta(seconds=30),
            {
                "notBefore": _NOW + timedelta(seconds=31),
                "expiresAt": _NOW + timedelta(seconds=120),
            },
        ),
    ),
    ids=("expired", "not-yet-valid"),
)
def test_expired_or_not_yet_valid_authorization_fails_closed(
    authorization_context: SimpleNamespace,
    clock: datetime,
    overrides: dict[str, object],
) -> None:
    bundle = _signed(_statement(authorization_context, **overrides))

    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="not currently valid"):
        _verify(authorization_context, bundle, verifier=_verifier(clock=clock))


def test_exact_not_before_boundary_is_valid(authorization_context: SimpleNamespace) -> None:
    statement = _statement(
        authorization_context,
        notBefore=_NOW + timedelta(seconds=30),
    )

    verified = _verify(
        authorization_context,
        _signed(statement),
        verifier=_verifier(clock=_NOW + timedelta(seconds=30)),
    )

    assert verified.validity_bound is True


def test_statement_rejects_unbounded_empty_and_naive_validity(
    authorization_context: SimpleNamespace,
) -> None:
    with pytest.raises(ValidationError, match="exceeds 180 seconds"):
        _statement(
            authorization_context,
            expiresAt=_NOW + timedelta(seconds=181),
        )
    with pytest.raises(ValidationError, match="validity window is inconsistent"):
        _statement(authorization_context, expiresAt=_NOW)
    with pytest.raises(ValidationError, match="timezone-aware"):
        _statement(authorization_context, issuedAt=_NOW.replace(tzinfo=None))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("liveRequestDigest", "e" * 64),
        ("providerChatRequestDigest", "d" * 64),
        ("modelId", "different-model"),
        ("capacityPinDigest", "c" * 64),
        ("transportPinDigest", "b" * 64),
        ("transportVersion", "pajin.web-analysis.provider-transport/v1"),
    ),
)
def test_validly_signed_exact_binding_mismatch_fails_closed(
    authorization_context: SimpleNamespace,
    field: str,
    value: object,
) -> None:
    data = _statement_data(authorization_context)
    data[field] = value
    if field == "transportVersion":
        with pytest.raises(ValidationError):
            WebAnalysisOneCallAuthorizationStatement.model_validate(data)
        return
    bundle = _signed(WebAnalysisOneCallAuthorizationStatement.model_validate(data))

    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="exact live input"):
        _verify(authorization_context, bundle)


def test_signature_unknown_key_and_foreign_anchor_fail_closed(
    authorization_context: SimpleNamespace,
) -> None:
    statement = _statement(authorization_context)
    bundle = _signed(statement)
    wire = bundle.model_dump(mode="python", by_alias=True)
    wire["signatureBase64url"] = _base64url(b"\x00" * 64)
    forged = SignedWebAnalysisOneCallAuthorization.model_validate(wire)
    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="signature verification"):
        _verify(authorization_context, forged)

    unknown_key_statement = _statement(
        authorization_context,
        signingKeyId="unknown-key-v1",
    )
    unknown_key_bundle = _signed(unknown_key_statement, key_id="unknown-key-v1")
    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="absent"):
        _verify(authorization_context, unknown_key_bundle)

    foreign_anchor = _trust_anchor(issuer="other-authorizer.invalid")
    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="not trusted"):
        _verify(
            authorization_context,
            bundle,
            verifier=_verifier(anchor=foreign_anchor),
        )


@pytest.mark.parametrize(
    "state",
    (
        WebAnalysisOneCallAuthorizationKeyState.RETIRED,
        WebAnalysisOneCallAuthorizationKeyState.REVOKED,
    ),
)
def test_retired_or_revoked_signing_key_fails_closed(
    authorization_context: SimpleNamespace,
    state: WebAnalysisOneCallAuthorizationKeyState,
) -> None:
    anchor = _inactive_signing_anchor(state)
    bundle = _signed(_statement(authorization_context))

    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="not active"):
        _verify(
            authorization_context,
            bundle,
            verifier=_verifier(anchor=anchor),
        )


def test_bundle_key_id_is_covered_by_the_signed_statement(
    authorization_context: SimpleNamespace,
) -> None:
    bundle = _signed(_statement(authorization_context))
    substituted = bundle.model_dump(mode="python", by_alias=True)
    substituted["keyId"] = "different-key-v1"

    with pytest.raises(ValidationError, match="bundle key differs"):
        SignedWebAnalysisOneCallAuthorization.model_validate(substituted)


def test_independent_trust_anchor_digest_is_required() -> None:
    anchor = _trust_anchor()

    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="configuration failed"):
        WebAnalysisOneCallAuthorizationVerifier(
            trust_anchor=anchor,
            expected_trust_anchor_digest="0" * 64,
        )


def test_trust_anchor_drift_is_rechecked_for_every_verification(
    authorization_context: SimpleNamespace,
) -> None:
    verifier = _verifier()
    object.__setattr__(verifier, "trust_anchor", _trust_anchor(issuer="drift.invalid"))

    with pytest.raises(WebAnalysisOneCallAuthorizationError, match="drifted"):
        _verify(
            authorization_context,
            _signed(_statement(authorization_context)),
            verifier=verifier,
        )


def test_authority_widening_and_non_boolean_false_are_rejected(
    authorization_context: SimpleNamespace,
) -> None:
    base = _statement_data(authorization_context)
    for alias in _AUTHORITY_FALSE_ALIASES:
        widened = {**base, alias: True}
        with pytest.raises(ValidationError, match="literal false"):
            WebAnalysisOneCallAuthorizationStatement.model_validate(widened)
    with pytest.raises(ValidationError, match="literal false"):
        WebAnalysisOneCallAuthorizationStatement.model_validate(
            {**base, "targetRequestAuthority": 0}
        )


@pytest.mark.parametrize("nonce", ("too-short", "contains whitespace 012345", "x" * 257))
def test_nonce_shape_is_bounded_and_whitespace_free(
    authorization_context: SimpleNamespace,
    nonce: str,
) -> None:
    with pytest.raises(ValidationError):
        _statement(authorization_context, nonce=nonce)


def test_strict_parsers_reject_ambiguous_or_unbounded_input(
    authorization_context: SimpleNamespace,
) -> None:
    bundle = _signed(_statement(authorization_context))
    anchor = _trust_anchor()
    assert (
        parse_signed_web_analysis_one_call_authorization(
            bundle.model_dump_json(by_alias=True).encode("utf-8")
        )
        == bundle
    )
    assert (
        parse_web_analysis_one_call_authorization_trust_anchor(
            anchor.model_dump_json(by_alias=True).encode("utf-8")
        )
        == anchor
    )
    with pytest.raises(WebAnalysisOneCallAuthorizationError):
        parse_signed_web_analysis_one_call_authorization(b'{"x":1,"x":2}')
    with pytest.raises(WebAnalysisOneCallAuthorizationError):
        parse_signed_web_analysis_one_call_authorization(b" " * (512 * 1024 + 1))
    with pytest.raises(WebAnalysisOneCallAuthorizationError):
        parse_web_analysis_one_call_authorization_trust_anchor(b"\xff")
    unknown = bundle.model_dump(mode="json", by_alias=True)
    unknown["campaignApproval"] = {"approved": True}
    with pytest.raises(WebAnalysisOneCallAuthorizationError):
        parse_signed_web_analysis_one_call_authorization(
            canonical_json_bytes(
                unknown,
                label="authorization with an unknown field",
                max_bytes=512 * 1024,
            )
        )


def test_campaign_approval_and_raw_coordinates_cannot_be_reinterpreted(
    authorization_context: SimpleNamespace,
) -> None:
    verifier = _verifier()
    rejected = (
        LocalWebAssessmentAuthorization.model_construct(),
        ActionApprovalEnvelope.model_construct(),
        _verify(authorization_context, _signed(_statement(authorization_context))).coordinate,
    )
    for value in rejected:
        with pytest.raises(WebAnalysisOneCallAuthorizationError, match="failed closed"):
            verifier.verify(
                cast(Any, value),
                admission=authorization_context.admission,
                live_request=authorization_context.live_request,
                capacity_pin=authorization_context.capacity_pin,
                transport_pin=authorization_context.transport_pin,
            )


def test_same_nonce_has_one_durable_authorization_identity_across_preparations(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    context = authorization_context
    second_admission_data = context.admission.model_dump(mode="python", by_alias=True)
    second_admission_data.update(
        {
            "admissionId": "",
            "admissionDigest": "",
            "preparationRunId": "run_20990101T000000Z_deadbeef",
            "preparationRunRootDigest": "5" * 64,
            "preparationDigest": "6" * 64,
            "preparationIndexDigest": "7" * 64,
        }
    )
    second_admission = type(context.admission).model_validate(second_admission_data)
    second_context = SimpleNamespace(
        admission=second_admission,
        live_request=context.live_request,
        capacity_pin=context.capacity_pin,
        transport_pin=context.transport_pin,
    )
    nonce = "shared-nonce-0123456789abcdef"
    first = _verify(context, _signed(_statement(context, nonce=nonce)))
    second = _verify(
        second_context,
        _signed(
            _statement(
                second_context,
                nonce=nonce,
                issuedAt=_NOW + timedelta(seconds=1),
                notBefore=_NOW + timedelta(seconds=1),
                expiresAt=_NOW + timedelta(seconds=121),
            )
        ),
    )
    assert first.authorization_envelope_digest != second.authorization_envelope_digest
    assert first.preparation_identity != second.preparation_identity
    assert first.coordinate.authorization_identity == second.coordinate.authorization_identity

    journal = WebAnalysisLiveClaimJournal(
        tmp_path / "claims.sqlite3",
        clock=lambda: _NOW,
        allow_create=True,
    )
    first_binding = build_web_analysis_live_claim_binding(
        admission=context.admission,
        authorization=first.coordinate,
    )
    second_binding = build_web_analysis_live_claim_binding(
        admission=second_context.admission,
        authorization=second.coordinate,
    )
    journal.reserve(first_binding)
    with pytest.raises(WebAnalysisLiveClaimJournalError):
        journal.reserve(second_binding)

    entry = journal.inspect_authorization(first.coordinate.authorization_identity)
    assert entry is not None
    assert entry.binding.claim_id == first_binding.claim_id
    assert entry.phase is WebAnalysisLiveClaimPhase.RESERVATION
    assert entry.dispatch_count == 0
    assert entry.reusable is False
    assert journal.inspect(second_binding.claim_id) is None


def test_production_verifier_has_no_signer_or_execution_imports() -> None:
    source_path = Path(authorization_module.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
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
    assert "Ed25519PrivateKey" not in source_path.read_text(encoding="utf-8")
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"sign", "issue", "approve"}
        for node in ast.walk(tree)
    )
