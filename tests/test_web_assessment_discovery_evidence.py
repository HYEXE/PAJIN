from __future__ import annotations

from copy import deepcopy
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.web_assessment.discovery import (
    BrowserDiscoveryPlan,
    BrowserDiscoveryResult,
    DiscoveredBrowserRoute,
    browser_discovery_plan,
)
from pajin.web_assessment.discovery_evidence import (
    AUTHENTICATED_DISCOVERY_EVIDENCE_API_VERSION,
    AuthenticatedDiscoveryEvidence,
    authenticated_discovery_evidence,
)
from pajin.web_assessment.models import (
    PassiveDiscoveryBoundaryReceipt,
    RequestEvidence,
    request_evidence_digest,
)

_ORIGIN = "http://127.0.0.1:4317"


def _result(plan: BrowserDiscoveryPlan) -> BrowserDiscoveryResult:
    return BrowserDiscoveryResult(
        plan_digest=plan.plan_digest,
        origin=plan.origin,
        routes=(
            DiscoveredBrowserRoute(
                route="/",
                depth=0,
                source="seed",
            ),
        ),
        forms=(),
        rejected_candidates={},
        route_limit_reached=False,
        form_limit_reached=False,
        field_limit_reached=False,
    )


def _request(sequence: int, suffix: str, *, path: str = "/asset.js") -> RequestEvidence:
    return RequestEvidence(
        evidence_id=f"http-{sequence}-{suffix}",
        phase="browser-passive-discovery",
        method="GET",
        path=path,
        request_sha256="a" * 64,
        status=200,
        response_sha256=sha256(b"").hexdigest(),
        response_bytes=0,
        media_type="application/javascript",
    )


def _receipt(
    request: RequestEvidence,
    *,
    origin: str = _ORIGIN,
    observed_response_body_bytes: int = 2_048,
) -> PassiveDiscoveryBoundaryReceipt:
    sequence = int(request.evidence_id.split("-", maxsplit=2)[1])
    return PassiveDiscoveryBoundaryReceipt(
        evidenceId=request.evidence_id,
        requestEvidenceDigest=request_evidence_digest(request),
        reservationSequence=sequence,
        evidenceSequence=sequence,
        canonicalOrigin=origin,
        method="GET",
        queryPresent=False,
        requestBytes=0,
        redirectHops=0,
        path=request.path,
        status=request.status,
        observedResponseBodyBytes=observed_response_body_bytes,
        retainedResponseBytes=request.response_bytes,
        retainedResponseSha256=request.response_sha256,
        mediaType=request.media_type,
    )


def _evidence() -> AuthenticatedDiscoveryEvidence:
    plan = browser_discovery_plan(
        _ORIGIN,
        limits={"max_routes": 1, "settle_milliseconds": 0},
    )
    requests = (
        _request(7, "aaaaaaaa"),
        _request(8, "bbbbbbbb", path="/"),
    )
    return authenticated_discovery_evidence(
        discovery_plan=plan,
        discovery_result=_result(plan),
        request_evidence=requests,
        boundary_receipts=tuple(_receipt(request) for request in requests),
    )


def test_authenticated_discovery_evidence_is_content_addressed_and_proposal_only() -> None:
    evidence = _evidence()

    assert evidence.api_version == AUTHENTICATED_DISCOVERY_EVIDENCE_API_VERSION
    assert evidence.semantics == "proposal-only"
    assert evidence.passive_methods == ("GET",)
    assert len(evidence.request_evidence_digest) == 64
    assert len(evidence.boundary_receipts_digest) == 64
    assert len(evidence.evidence_digest) == 64
    assert tuple(receipt.evidence_id for receipt in evidence.boundary_receipts) == tuple(
        request.evidence_id for request in evidence.request_evidence
    )
    assert evidence.authenticated is True
    assert evidence.browser_closed is True
    assert evidence.exact_origin_only is True
    assert evidence.query_free_only is True
    assert evidence.bodyless_requests_only is True
    assert evidence.redirects_followed is False
    assert evidence.request_payloads_sent is False
    assert evidence.response_bodies_retained is False
    assert evidence.raw_dom_retained is False
    assert evidence.screenshots_retained is False
    assert evidence.form_values_retained is False
    assert evidence.forms_submitted is False
    assert evidence.credentials_persisted is False
    assert evidence.external_delivery_performed is False
    assert evidence.scope_expansion_authority is False
    assert evidence.action_permit_authority is False
    assert evidence.form_submission_authority is False
    assert evidence.payload_authority is False
    assert evidence.graph_admission_authority is False
    assert evidence.finding_authority is False
    assert evidence.execution_authority is False

    round_trip = AuthenticatedDiscoveryEvidence.model_validate(
        evidence.model_dump(mode="json", by_alias=True)
    )
    assert round_trip == evidence


def test_authenticated_discovery_evidence_rejects_request_digest_tampering() -> None:
    raw = _evidence().model_dump(mode="json", by_alias=True)
    raw["requestEvidenceDigest"] = "0" * 64

    with pytest.raises(ValidationError, match="request Evidence Digest differs"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)


def test_passive_boundary_receipt_is_strict_content_addressed_observation() -> None:
    receipt = _evidence().boundary_receipts[0]

    assert receipt.canonical_origin == _ORIGIN
    assert receipt.method == "GET"
    assert receipt.query_present is False
    assert receipt.request_bytes == 0
    assert receipt.redirect_hops == 0
    assert receipt.observed_response_body_bytes == 2_048
    assert receipt.retained_response_bytes == 0
    assert receipt.retained_response_sha256 == sha256(b"").hexdigest()
    assert receipt.reservation_sequence == receipt.evidence_sequence == 7
    assert len(receipt.receipt_digest) == 64
    assert (
        PassiveDiscoveryBoundaryReceipt.model_validate(
            receipt.model_dump(mode="json", by_alias=True)
        )
        == receipt
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("queryPresent", True, "query marker"),
        ("queryPresent", 0, "query marker"),
        ("requestBytes", 1, "counters"),
        ("requestBytes", False, "counters"),
        ("redirectHops", 1, "counters"),
        ("retainedResponseBytes", 1, "counters"),
        ("reservationSequence", True, "valid integer"),
        ("observedResponseBodyBytes", False, "valid integer"),
        ("method", "HEAD", "Input should be 'GET'"),
    ),
)
def test_passive_boundary_receipt_rejects_non_exact_boundary_fields(
    field: str,
    value: object,
    message: str,
) -> None:
    raw = _evidence().boundary_receipts[0].model_dump(mode="json", by_alias=True)
    raw[field] = value
    raw.pop("receiptDigest")

    with pytest.raises(ValidationError, match=message):
        PassiveDiscoveryBoundaryReceipt.model_validate(raw)


def test_passive_boundary_receipt_rejects_digest_and_sequence_tampering() -> None:
    raw = _evidence().boundary_receipts[0].model_dump(mode="json", by_alias=True)
    raw["receiptDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="Receipt Digest differs"):
        PassiveDiscoveryBoundaryReceipt.model_validate(raw)

    raw = _evidence().boundary_receipts[0].model_dump(mode="json", by_alias=True)
    raw["evidenceSequence"] = 8
    raw.pop("receiptDigest")
    with pytest.raises(ValidationError, match="Evidence sequence differs"):
        PassiveDiscoveryBoundaryReceipt.model_validate(raw)


@pytest.mark.parametrize(
    "media_type",
    (
        "text/html; charset=utf-8",
        "Text/HTML",
        "text/plain\nsecond-line",
        "not-a-media-type",
    ),
)
def test_passive_boundary_receipt_requires_canonical_media_type_essence(
    media_type: str,
) -> None:
    raw = _evidence().boundary_receipts[0].model_dump(mode="json", by_alias=True)
    raw["mediaType"] = media_type
    raw.pop("receiptDigest")

    with pytest.raises(ValidationError, match="canonical Content-Type essence"):
        PassiveDiscoveryBoundaryReceipt.model_validate(raw)


def test_authenticated_discovery_evidence_rejects_aggregate_digest_tampering() -> None:
    raw = _evidence().model_dump(mode="json", by_alias=True)
    raw["evidenceDigest"] = "0" * 64

    with pytest.raises(ValidationError, match="authenticated discovery Evidence Digest differs"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)


def test_authenticated_discovery_evidence_rejects_receipt_set_digest_tampering() -> None:
    raw = _evidence().model_dump(mode="json", by_alias=True)
    raw["boundaryReceiptsDigest"] = "0" * 64

    with pytest.raises(ValidationError, match="boundary Receipts Digest differs"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("requestEvidenceDigest", "0" * 64),
        ("canonicalOrigin", "http://127.0.0.1:4318"),
        ("path", "/foreign.js"),
        ("status", 201),
        ("mediaType", "text/plain"),
    ),
)
def test_authenticated_discovery_evidence_rejects_receipt_request_drift(
    field: str,
    value: object,
) -> None:
    raw = _evidence().model_dump(mode="json", by_alias=True)
    receipt = deepcopy(raw["boundaryReceipts"][0])
    assert isinstance(receipt, dict)
    receipt[field] = value
    receipt.pop("receiptDigest")
    raw["boundaryReceipts"][0] = receipt
    raw.pop("boundaryReceiptsDigest")
    raw.pop("evidenceDigest")

    with pytest.raises(ValidationError, match="Receipt differs from exact request Evidence"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)


def test_authenticated_discovery_evidence_rejects_foreign_plan() -> None:
    evidence = _evidence()
    foreign = browser_discovery_plan(
        _ORIGIN,
        limits={"max_routes": 2, "settle_milliseconds": 0},
    )
    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["discoveryPlan"] = foreign.model_dump(mode="json")
    raw.pop("evidenceDigest")

    with pytest.raises(ValidationError, match="Result differs from its exact Plan"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)


def test_authenticated_discovery_evidence_revalidates_nested_model_instances() -> None:
    evidence = _evidence()
    stale_plan = evidence.discovery_plan.model_copy(update={"max_routes": 2})
    invalid_result = evidence.discovery_result.model_copy(update={"routes": ()})
    invalid_request = evidence.request_evidence[0].model_copy(update={"request_sha256": "invalid"})
    invalid_receipt = evidence.boundary_receipts[0].model_copy(update={"query_present": 0})

    with pytest.raises(ValidationError, match="browser discovery Plan Digest differs"):
        AuthenticatedDiscoveryEvidence(
            discoveryPlan=stale_plan,
            discoveryResult=evidence.discovery_result,
            requestEvidence=evidence.request_evidence,
            boundaryReceipts=evidence.boundary_receipts,
        )
    with pytest.raises(ValidationError):
        AuthenticatedDiscoveryEvidence(
            discoveryPlan=evidence.discovery_plan,
            discoveryResult=invalid_result,
            requestEvidence=evidence.request_evidence,
            boundaryReceipts=evidence.boundary_receipts,
        )
    with pytest.raises(ValidationError):
        AuthenticatedDiscoveryEvidence(
            discoveryPlan=evidence.discovery_plan,
            discoveryResult=evidence.discovery_result,
            requestEvidence=(invalid_request,),
            boundaryReceipts=(evidence.boundary_receipts[0],),
        )
    with pytest.raises(ValidationError, match="query marker"):
        AuthenticatedDiscoveryEvidence(
            discoveryPlan=evidence.discovery_plan,
            discoveryResult=evidence.discovery_result,
            requestEvidence=(evidence.request_evidence[0],),
            boundaryReceipts=(invalid_receipt,),
        )


@pytest.mark.parametrize(
    "field",
    (
        "redirectsFollowed",
        "requestPayloadsSent",
        "responseBodiesRetained",
        "rawDomRetained",
        "screenshotsRetained",
        "formValuesRetained",
        "formsSubmitted",
        "credentialsPersisted",
        "externalDeliveryPerformed",
        "scopeExpansionAuthority",
        "actionPermitAuthority",
        "formSubmissionAuthority",
        "payloadAuthority",
        "graphAdmissionAuthority",
        "findingAuthority",
        "executionAuthority",
    ),
)
def test_authenticated_discovery_evidence_rejects_flipped_negative_marker(field: str) -> None:
    raw = _evidence().model_dump(mode="json", by_alias=True)
    raw[field] = True

    with pytest.raises(ValidationError, match="markers must be false"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)


@pytest.mark.parametrize(
    "field",
    (
        "authenticated",
        "browserClosed",
        "exactOriginOnly",
        "queryFreeOnly",
        "bodylessRequestsOnly",
    ),
)
def test_authenticated_discovery_evidence_rejects_false_or_coerced_enforcement_marker(
    field: str,
) -> None:
    for invalid in (False, 1, "true"):
        raw = _evidence().model_dump(mode="json", by_alias=True)
        raw[field] = invalid
        with pytest.raises(ValidationError, match="markers must be boolean true"):
            AuthenticatedDiscoveryEvidence.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("phase", "browser-authentication"),
        ("method", "HEAD"),
        ("method", "POST"),
        ("response_bytes", 1),
        ("response_sha256", "b" * 64),
    ),
)
def test_authenticated_discovery_evidence_rejects_non_passive_request_metadata(
    field: str,
    value: object,
) -> None:
    raw = _evidence().model_dump(mode="json", by_alias=True)
    request = deepcopy(raw["requestEvidence"][0])
    assert isinstance(request, dict)
    request[field] = value
    raw["requestEvidence"][0] = request
    raw.pop("requestEvidenceDigest")
    raw.pop("evidenceDigest")

    with pytest.raises(ValidationError, match="passive bodyless GET metadata"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)


def test_authenticated_discovery_evidence_rejects_duplicate_or_reordered_requests() -> None:
    evidence = _evidence()
    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["requestEvidence"] = list(reversed(raw["requestEvidence"]))
    raw.pop("requestEvidenceDigest")
    raw.pop("evidenceDigest")
    with pytest.raises(ValidationError, match="must be ordered"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)

    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["requestEvidence"] = [raw["requestEvidence"][0], raw["requestEvidence"][0]]
    raw.pop("requestEvidenceDigest")
    raw.pop("evidenceDigest")
    with pytest.raises(ValidationError, match="IDs must be unique"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)


def test_authenticated_discovery_evidence_rejects_reordered_or_duplicate_receipts() -> None:
    evidence = _evidence()
    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["boundaryReceipts"] = list(reversed(raw["boundaryReceipts"]))
    raw.pop("boundaryReceiptsDigest")
    raw.pop("evidenceDigest")
    with pytest.raises(ValidationError, match="differ from request Evidence order"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)

    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["boundaryReceipts"] = [raw["boundaryReceipts"][0], raw["boundaryReceipts"][0]]
    raw.pop("boundaryReceiptsDigest")
    raw.pop("evidenceDigest")
    with pytest.raises(ValidationError, match="differ from request Evidence order"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)


def test_authenticated_discovery_evidence_builder_canonicalizes_completion_order() -> None:
    plan = browser_discovery_plan(
        _ORIGIN,
        limits={"max_routes": 1, "settle_milliseconds": 0},
    )

    later = _request(8, "bbbbbbbb", path="/")
    earlier = _request(7, "aaaaaaaa")
    evidence = authenticated_discovery_evidence(
        discovery_plan=plan,
        discovery_result=_result(plan),
        request_evidence=(later, earlier),
        boundary_receipts=(_receipt(later), _receipt(earlier)),
    )

    assert tuple(item.evidence_id for item in evidence.request_evidence) == (
        "http-7-aaaaaaaa",
        "http-8-bbbbbbbb",
    )
    assert tuple(item.evidence_id for item in evidence.boundary_receipts) == (
        "http-7-aaaaaaaa",
        "http-8-bbbbbbbb",
    )


@pytest.mark.parametrize(
    "field",
    (
        "raw_dom_retained",
        "screenshots_retained",
        "form_values_retained",
        "forms_submitted",
        "external_delivery_performed",
        "graph_admission_authority",
        "finding_authority",
        "execution_authority",
    ),
)
@pytest.mark.parametrize("invalid", (True, 0, "false", None))
def test_authenticated_discovery_evidence_revalidates_result_false_markers(
    field: str,
    invalid: object,
) -> None:
    raw = _evidence().model_dump(mode="json", by_alias=True)
    result = deepcopy(raw["discoveryResult"])
    assert isinstance(result, dict)
    result[field] = invalid
    raw["discoveryResult"] = result
    raw.pop("evidenceDigest")

    with pytest.raises(ValidationError, match="Result markers must be explicit boolean false"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)


def test_authenticated_discovery_evidence_forbids_extra_authority_input() -> None:
    raw = _evidence().model_dump(mode="json", by_alias=True)
    raw["executableRoutes"] = ["/admin"]

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AuthenticatedDiscoveryEvidence.model_validate(raw)
