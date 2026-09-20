"""Content-addressed, proposal-only evidence for authenticated passive discovery.

The aggregate in this module is intentionally not execution, Graph-admission, or Finding
authority.  It binds one exact discovery Plan and Result to the bodyless GET response metadata
retained by the authenticated passive browser boundary.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Final, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import StrictModel
from pajin.web_assessment.discovery import BrowserDiscoveryPlan, BrowserDiscoveryResult
from pajin.web_assessment.models import (
    PassiveDiscoveryBoundaryReceipt,
    RequestEvidence,
    request_evidence_digest,
    request_evidence_sequence,
)

AUTHENTICATED_DISCOVERY_EVIDENCE_API_VERSION: Final[
    Literal["pajin.dev/authenticated-passive-discovery-evidence/v1alpha1"]
] = "pajin.dev/authenticated-passive-discovery-evidence/v1alpha1"

_EMPTY_RESPONSE_SHA256: Final[str] = hashlib.sha256(b"").hexdigest()
_RESULT_FALSE_MARKERS: Final[tuple[str, ...]] = (
    "raw_dom_retained",
    "screenshots_retained",
    "form_values_retained",
    "forms_submitted",
    "external_delivery_performed",
    "graph_admission_authority",
    "finding_authority",
    "execution_authority",
)


class AuthenticatedDiscoveryEvidence(StrictModel):
    """One inert discovery proposal set with explicit retention and authority boundaries."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/authenticated-passive-discovery-evidence/v1alpha1"] = Field(
        default=AUTHENTICATED_DISCOVERY_EVIDENCE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AuthenticatedDiscoveryEvidence"] = "AuthenticatedDiscoveryEvidence"
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    semantics: Literal["proposal-only"] = "proposal-only"
    discovery_plan: BrowserDiscoveryPlan = Field(alias="discoveryPlan")
    discovery_result: BrowserDiscoveryResult = Field(alias="discoveryResult")
    request_evidence: tuple[RequestEvidence, ...] = Field(
        alias="requestEvidence",
        min_length=1,
        max_length=500,
    )
    request_evidence_digest: str = Field(
        default="",
        alias="requestEvidenceDigest",
        max_length=64,
    )
    boundary_receipts: tuple[PassiveDiscoveryBoundaryReceipt, ...] = Field(
        alias="boundaryReceipts",
        min_length=1,
        max_length=500,
    )
    boundary_receipts_digest: str = Field(
        default="",
        alias="boundaryReceiptsDigest",
        max_length=64,
    )
    passive_methods: tuple[Literal["GET"], ...] = Field(
        default=("GET",),
        alias="passiveMethods",
        min_length=1,
        max_length=1,
    )
    authenticated: Literal[True] = True
    browser_closed: Literal[True] = Field(default=True, alias="browserClosed")
    exact_origin_only: Literal[True] = Field(default=True, alias="exactOriginOnly")
    query_free_only: Literal[True] = Field(default=True, alias="queryFreeOnly")
    bodyless_requests_only: Literal[True] = Field(
        default=True,
        alias="bodylessRequestsOnly",
    )
    redirects_followed: Literal[False] = Field(default=False, alias="redirectsFollowed")
    request_payloads_sent: Literal[False] = Field(default=False, alias="requestPayloadsSent")
    response_bodies_retained: Literal[False] = Field(
        default=False,
        alias="responseBodiesRetained",
    )
    raw_dom_retained: Literal[False] = Field(default=False, alias="rawDomRetained")
    screenshots_retained: Literal[False] = Field(default=False, alias="screenshotsRetained")
    form_values_retained: Literal[False] = Field(default=False, alias="formValuesRetained")
    forms_submitted: Literal[False] = Field(default=False, alias="formsSubmitted")
    credentials_persisted: Literal[False] = Field(default=False, alias="credentialsPersisted")
    external_delivery_performed: Literal[False] = Field(
        default=False,
        alias="externalDeliveryPerformed",
    )
    scope_expansion_authority: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthority",
    )
    action_permit_authority: Literal[False] = Field(
        default=False,
        alias="actionPermitAuthority",
    )
    form_submission_authority: Literal[False] = Field(
        default=False,
        alias="formSubmissionAuthority",
    )
    payload_authority: Literal[False] = Field(default=False, alias="payloadAuthority")
    graph_admission_authority: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthority",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator(
        "authenticated",
        "browser_closed",
        "exact_origin_only",
        "query_free_only",
        "bodyless_requests_only",
        mode="before",
    )
    @classmethod
    def require_true_markers(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("authenticated discovery enforcement markers must be boolean true")
        return value

    @field_validator(
        "redirects_followed",
        "request_payloads_sent",
        "response_bodies_retained",
        "raw_dom_retained",
        "screenshots_retained",
        "form_values_retained",
        "forms_submitted",
        "credentials_persisted",
        "external_delivery_performed",
        "scope_expansion_authority",
        "action_permit_authority",
        "form_submission_authority",
        "payload_authority",
        "graph_admission_authority",
        "finding_authority",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError(
                "authenticated discovery retention and authority markers must be false"
            )
        return value

    @field_validator("discovery_result", mode="before")
    @classmethod
    def require_explicit_result_false_markers(cls, value: object) -> object:
        if isinstance(value, BrowserDiscoveryResult):
            markers = {name: getattr(value, name, None) for name in _RESULT_FALSE_MARKERS}
            payload: object = value.model_dump(mode="json", by_alias=True)
        elif isinstance(value, Mapping):
            markers = {name: value.get(name) for name in _RESULT_FALSE_MARKERS}
            payload = value
        else:
            return value
        if any(type(marker) is not bool or marker is not False for marker in markers.values()):
            raise ValueError(
                "authenticated discovery Result markers must be explicit boolean false"
            )
        return BrowserDiscoveryResult.model_validate(payload)

    @field_validator("discovery_plan", mode="before")
    @classmethod
    def canonicalize_discovery_plan(cls, value: object) -> object:
        if isinstance(value, BrowserDiscoveryPlan):
            return BrowserDiscoveryPlan.model_validate(value.model_dump(mode="json", by_alias=True))
        return value

    @field_validator("request_evidence", mode="before")
    @classmethod
    def canonicalize_request_evidence(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            return value
        return tuple(
            RequestEvidence.model_validate(
                request.model_dump(mode="json", by_alias=True)
                if isinstance(request, RequestEvidence)
                else request
            )
            for request in value
        )

    @field_validator("boundary_receipts", mode="before")
    @classmethod
    def canonicalize_boundary_receipts(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            return value
        return tuple(
            PassiveDiscoveryBoundaryReceipt.model_validate(
                receipt.model_dump(mode="json", by_alias=True)
                if isinstance(receipt, PassiveDiscoveryBoundaryReceipt)
                else receipt
            )
            for receipt in value
        )

    @model_validator(mode="after")
    def bind_evidence(self) -> Self:
        plan = self.discovery_plan
        result = self.discovery_result
        if result.plan_digest != plan.plan_digest or result.origin != plan.origin:
            raise ValueError("authenticated discovery Result differs from its exact Plan")
        if (
            result.raw_dom_retained
            or result.screenshots_retained
            or result.form_values_retained
            or result.forms_submitted
            or result.external_delivery_performed
            or result.graph_admission_authority
            or result.finding_authority
            or result.execution_authority
        ):
            raise ValueError(
                "authenticated discovery Result claims forbidden authority or retention"
            )
        if self.passive_methods != ("GET",):
            raise ValueError("authenticated discovery methods must be exactly GET")

        sequences: list[int] = []
        evidence_ids: set[str] = set()
        for request in self.request_evidence:
            sequences.append(request_evidence_sequence(request))
            if request.evidence_id in evidence_ids:
                raise ValueError("authenticated discovery request Evidence IDs must be unique")
            evidence_ids.add(request.evidence_id)
            if (
                request.phase != "browser-passive-discovery"
                or request.method != "GET"
                or request.response_bytes != 0
                or request.response_sha256 != _EMPTY_RESPONSE_SHA256
            ):
                raise ValueError(
                    "authenticated discovery request Evidence must be passive bodyless GET metadata"
                )
        if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
            raise ValueError("authenticated discovery request Evidence must be ordered")

        receipt_evidence_ids = tuple(receipt.evidence_id for receipt in self.boundary_receipts)
        request_evidence_ids = tuple(request.evidence_id for request in self.request_evidence)
        if receipt_evidence_ids != request_evidence_ids:
            raise ValueError(
                "authenticated discovery boundary Receipts differ from request Evidence order"
            )
        receipt_digests: set[str] = set()
        for request, receipt in zip(
            self.request_evidence,
            self.boundary_receipts,
            strict=True,
        ):
            sequence = request_evidence_sequence(request)
            if receipt.receipt_digest in receipt_digests:
                raise ValueError("authenticated discovery boundary Receipt Digests must be unique")
            receipt_digests.add(receipt.receipt_digest)
            if (
                receipt.request_evidence_digest != request_evidence_digest(request)
                or receipt.reservation_sequence != sequence
                or receipt.evidence_sequence != sequence
                or receipt.canonical_origin != plan.origin
                or receipt.method != request.method
                or receipt.path != request.path
                or receipt.status != request.status
                or receipt.retained_response_bytes != request.response_bytes
                or receipt.retained_response_sha256 != request.response_sha256
                or receipt.media_type != request.media_type
            ):
                raise ValueError(
                    "authenticated discovery boundary Receipt differs from exact request Evidence"
                )

        request_material = [
            request.model_dump(mode="json", by_alias=True) for request in self.request_evidence
        ]
        expected_requests = discovery_digest(
            "pajin.web-assessment.authenticated-discovery-requests/v1",
            request_material,
        )
        if self.request_evidence_digest and self.request_evidence_digest != expected_requests:
            raise ValueError("authenticated discovery request Evidence Digest differs")
        object.__setattr__(self, "request_evidence_digest", expected_requests)

        receipt_material = [
            receipt.model_dump(mode="json", by_alias=True) for receipt in self.boundary_receipts
        ]
        expected_receipts = discovery_digest(
            "pajin.web-assessment.authenticated-discovery-boundary-receipts/v1",
            receipt_material,
        )
        if self.boundary_receipts_digest and self.boundary_receipts_digest != expected_receipts:
            raise ValueError("authenticated discovery boundary Receipts Digest differs")
        object.__setattr__(self, "boundary_receipts_digest", expected_receipts)

        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evidence_digest"},
        )
        expected = discovery_digest(
            "pajin.web-assessment.authenticated-discovery-evidence/v1",
            material,
        )
        if self.evidence_digest and self.evidence_digest != expected:
            raise ValueError("authenticated discovery Evidence Digest differs")
        object.__setattr__(self, "evidence_digest", expected)
        return self


def authenticated_discovery_evidence(
    *,
    discovery_plan: BrowserDiscoveryPlan,
    discovery_result: BrowserDiscoveryResult,
    request_evidence: tuple[RequestEvidence, ...],
    boundary_receipts: tuple[PassiveDiscoveryBoundaryReceipt, ...],
) -> AuthenticatedDiscoveryEvidence:
    """Build one canonical proposal-only aggregate without accepting authority flags."""

    return AuthenticatedDiscoveryEvidence(
        discoveryPlan=discovery_plan,
        discoveryResult=discovery_result,
        requestEvidence=tuple(sorted(request_evidence, key=request_evidence_sequence)),
        boundaryReceipts=tuple(
            sorted(boundary_receipts, key=lambda receipt: receipt.evidence_sequence)
        ),
    )


__all__ = [
    "AUTHENTICATED_DISCOVERY_EVIDENCE_API_VERSION",
    "AuthenticatedDiscoveryEvidence",
    "authenticated_discovery_evidence",
]
