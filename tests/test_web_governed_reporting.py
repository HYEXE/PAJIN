from __future__ import annotations

import copy
import inspect
import json
import os
import pickle
import sqlite3
import stat
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast

import pytest
from pydantic import JsonValue, ValidationError

import pajin.web_assessment.governed_reporting as reporting
from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import AutonomyLevel, ToolRiskTier
from pajin.graph import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphLineageVerificationError,
    GraphNodeKind,
    GraphProducerRegistry,
    GraphRelation,
    GraphSnapshotRef,
    SQLiteGraphEventLog,
    SQLiteGraphStore,
    parse_graph_proposal,
)
from pajin.graph.approval import (
    ActionApprovalAuthorization,
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalEnvelope,
    ActionApprovalIssuerAuthorityBinding,
    ActionApprovalReleaseRef,
    GraphApprovedActionPermitAuthority,
)
from pajin.graph.authority import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionCapabilityRegistry,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
    action_permit_attempt_id,
)
from pajin.graph.consistency import GraphDecision, GraphDecisionKind
from pajin.graph.projection import (
    GraphProjectionCoordinator,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    graph_snapshot_ref,
)
from pajin.graph.sqlite_store import _events_from_connection
from pajin.runtime.store import RunIntegrityVerification, RunStore, verify_run_integrity
from pajin.web_assessment.campaign import (
    LocalWebAssessmentCampaignResult,
    LocalWebAssessmentRunReference,
    local_web_assessment_run_reference,
    reconcile_local_web_assessment_runs,
)
from pajin.web_assessment.diagnostics import build_attack_paths
from pajin.web_assessment.governed_gateway import (
    WebGatewayCompletedActionAuthority,
    WebGatewayCompletionReceipt,
)
from pajin.web_assessment.governed_models import (
    WebAssessmentCapabilityGrantConsumptionReceipt,
    WebAssessmentCapabilityGrantConsumptionStore,
    WebAssessmentCapabilityGrantReservation,
)
from pajin.web_assessment.governed_worker import (
    HostLoopbackBrowserWorkerBackend,
    SignedWebWorkerActionEvidence,
    WebExecutionStatement,
    WebTargetIdentityStatement,
    WebWorkerAttestor,
    WebWorkerAuthorityBinding,
    WebWorkerCompletedActionAuthority,
    WebWorkerCompletedActionRecord,
    WebWorkerKeyState,
    WebWorkerRole,
    WebWorkerTrustRegistry,
    WebWorkerVerificationKey,
    canonical_web_worker_json,
    web_target_fingerprint_digest,
    web_worker_private_key_base64url,
    web_worker_public_key_base64url,
)
from pajin.web_assessment.models import (
    AssessmentIssue,
    BrowserPageEvidence,
    BrowserSessionSummary,
    IssueCheck,
    LocalWebAssessmentAuthorization,
    LocalWebAssessmentResult,
    ProbeTrial,
    RequestEvidence,
    WebAssessmentPlan,
    issue_observation,
)
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.verification import VerifiedLocalWebAssessmentSourceIntegrity
from pajin.workflow.validation_artifacts import (
    VERSIONED_VALIDATION_DECISIONS_PATH,
    VERSIONED_VALIDATION_REPORT_PATH,
)

NOW = datetime(2026, 9, 14, 3, 0, tzinfo=UTC)
ACTIVE_KEY_NOT_AFTER = datetime.max.replace(tzinfo=UTC)
ORIGIN = "http://127.0.0.1:3000"
TARGET_VERSION = "19.2.1-governed-reporting-test"
FINGERPRINT_ENDPOINT = "/rest/admin/application-version"
FINGERPRINT_BODY = canonical_web_worker_json({"version": TARGET_VERSION})
FINGERPRINT_RESPONSE_SHA256 = sha256(FINGERPRINT_BODY).hexdigest()
ADAPTER_IMPLEMENTATION_DIGEST = "a" * 64
RECIPE_DIGEST = juice_shop_plan(ORIGIN).plan_digest
ADAPTER_DIGEST = sha256(b"adapter").hexdigest()
ACCOUNT_RECEIPT_DIGEST = sha256(b"account-receipt").hexdigest()
CAMPAIGN_ID = "juice-shop-governed-local"
CAMPAIGN_DIGEST = sha256(b"campaign").hexdigest()
CAPABILITY_ID = "pajin.web.authenticated-assessment"
CAPABILITY_VERSION = "1.0.0"
CAPABILITY_DEFINITION_DIGEST = sha256(b"capability").hexdigest()


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _authorization(index: int) -> tuple[WebAssessmentPlan, LocalWebAssessmentAuthorization]:
    plan = juice_shop_plan(ORIGIN)
    return plan, LocalWebAssessmentAuthorization(
        plan_digest=plan.plan_digest,
        origin=plan.origin,
        approved_at=NOW - timedelta(minutes=5) + timedelta(seconds=index),
        expires_at=NOW + timedelta(minutes=20, seconds=index),
    )


def _requests() -> tuple[RequestEvidence, ...]:
    return tuple(
        RequestEvidence(
            evidence_id=f"http-{index}-{_digest(f'evidence-{index}')[:8]}",
            phase="governed-reporting-test",
            method="GET",
            path=f"/governed-reporting-test/{index}",
            request_sha256=_digest(f"request-{index}"),
            status=200,
            response_sha256=_digest(f"response-{index}"),
            response_bytes=index,
            media_type="application/json",
        )
        for index in range(1, 19)
    )


def _issue(
    check: IssueCheck,
    *,
    evidence_ids: tuple[str, ...],
) -> AssessmentIssue:
    severity: Literal["high", "medium"]
    facts: dict[str, JsonValue]
    if check == "sql-login":
        cwe, severity, evidence_count = "CWE-89", "high", 3
        facts = {
            "trueStatus": 200,
            "falseStatus": 401,
            "sessionMinted": True,
            "objectIdentityPresent": True,
            "authorizedDirectoryStatus": 200,
            "authorizedDirectoryRecordCount": 2,
            "credentialGuessUsed": False,
        }
    elif check == "object-access":
        cwe, severity, evidence_count = "CWE-639", "high", 3
        facts = {
            "attackAndTargetObjectsDiffer": True,
            "ownObjectReturned": True,
            "targetObjectReturned": True,
            "missingObjectReturned": False,
            "targetStatus": 200,
            "targetProductCount": 0,
            "targetWasDisposableAssessmentAccount": True,
        }
    else:
        cwe, severity, evidence_count = "CWE-79", "medium", 2
        facts = {
            "controlMarkerExecuted": False,
            "probeMarkerExecuted": True,
            "externalTransmission": False,
        }
    trials = (
        ProbeTrial(
            check=check,
            repetition="source",
            reproduced=True,
            controls_passed=True,
            evidence_ids=evidence_ids[:evidence_count],
            facts=facts,
        ),
        ProbeTrial(
            check=check,
            repetition="replay",
            reproduced=True,
            controls_passed=True,
            evidence_ids=evidence_ids[evidence_count : evidence_count * 2],
            facts=facts,
        ),
    )
    title, observed_impact = issue_observation(check, "locally-reproduced")
    issue_id = "web-issue:" + discovery_digest(
        "pajin.web-assessment.issue/v1",
        {
            "check": check,
            "cwe": cwe,
            "trials": [trial.model_dump(mode="json") for trial in trials],
        },
    )
    return AssessmentIssue(
        issue_id=issue_id,
        check=check,
        cwe=cwe,
        status="locally-reproduced",
        severity=severity,
        title=title,
        observed_impact=observed_impact,
        potential_impact=reporting._CHECK_CANONICAL_POTENTIAL_IMPACT[check],
        remediation=reporting._CHECK_CANONICAL_REMEDIATION[check],
        trials=trials,
    )


def _result(
    *,
    run_id: str,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    started_at: datetime,
) -> LocalWebAssessmentResult:
    requests = _requests()
    request_ids = tuple(item.evidence_id for item in requests)
    issues = (
        _issue("sql-login", evidence_ids=request_ids[:6]),
        _issue("object-access", evidence_ids=request_ids[6:12]),
        _issue("dom-xss", evidence_ids=request_ids[12:16]),
    )
    pages = tuple(
        BrowserPageEvidence(
            phase="authenticated-navigation",
            route=f"/#/governed-test-{index}",
            title="Juice Shop",
            ready_selector="app-root",
            dom_sha256=_digest(f"dom-{run_id}-{index}"),
            dom_bytes=100 + index,
            screenshot_reference=f"evidence/governed-{run_id[-8:]}-{index}.png",
            screenshot_sha256=_digest(f"screenshot-{run_id}-{index}"),
            screenshot_bytes=100 + index,
            captured_at=started_at + timedelta(seconds=index),
        )
        for index in (1, 2)
    )
    return LocalWebAssessmentResult(
        run_id=run_id,
        plan_name=plan.name,
        plan_digest=plan.plan_digest,
        authorization_id=authorization.authorization_id,
        origin=plan.origin,
        target_product="OWASP Juice Shop",
        target_version=TARGET_VERSION,
        started_at=started_at,
        finished_at=started_at + timedelta(seconds=3),
        browser=BrowserSessionSummary(
            authenticated=True,
            ephemeral_account_created=True,
            pages=pages,
            requests_completed=1,
            browser_closed=True,
        ),
        requests=requests,
        issues=issues,
        attack_paths=build_attack_paths(issues),
        account_retained_in_local_lab=True,
    )


def _verified_source(
    *,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    result: LocalWebAssessmentResult,
    index: int,
) -> VerifiedLocalWebAssessmentSourceIntegrity:
    return VerifiedLocalWebAssessmentSourceIntegrity(
        run_path=Path(f"/synthetic/governed-run-{index}"),
        verification=RunIntegrityVerification(
            run_id=result.run_id,
            seal_count=1,
            artifact_count=6,
            event_count=2,
            root_digest=_digest(f"root-{index}"),
        ),
        plan=plan,
        authorization=authorization,
        result=result,
        report_markdown="synthetic report",
        screenshot_references=tuple(page.screenshot_reference for page in result.browser.pages),
    )


def _campaign_result() -> tuple[
    LocalWebAssessmentRunReference,
    LocalWebAssessmentRunReference,
    LocalWebAssessmentCampaignResult,
    dict[str, VerifiedLocalWebAssessmentSourceIntegrity],
]:
    plan, source_authorization = _authorization(1)
    _, validation_authorization = _authorization(2)
    source_result = _result(
        run_id="run_20260914T030010Z_11111111",
        plan=plan,
        authorization=source_authorization,
        started_at=NOW + timedelta(seconds=10),
    )
    validation_result = _result(
        run_id="run_20260914T030030Z_22222222",
        plan=plan,
        authorization=validation_authorization,
        started_at=NOW + timedelta(seconds=30),
    )
    verified_source = _verified_source(
        plan=plan,
        authorization=source_authorization,
        result=source_result,
        index=1,
    )
    verified_validation = _verified_source(
        plan=plan,
        authorization=validation_authorization,
        result=validation_result,
        index=2,
    )
    source = local_web_assessment_run_reference(
        role="source",
        verified_source=verified_source,
    )
    validation = local_web_assessment_run_reference(
        role="validation",
        verified_source=verified_validation,
    )
    result = reconcile_local_web_assessment_runs(
        plan=plan,
        source=source,
        validation=validation,
        reconciled_at=NOW + timedelta(minutes=1),
    )
    return (
        source,
        validation,
        result,
        {
            source.run_id: verified_source,
            validation.run_id: verified_validation,
        },
    )


def _campaign_result_with_issue_field(
    *,
    field: Literal["cwe", "severity", "potential_impact", "remediation"],
    value: str,
) -> tuple[
    LocalWebAssessmentRunReference,
    LocalWebAssessmentRunReference,
    LocalWebAssessmentCampaignResult,
    dict[str, VerifiedLocalWebAssessmentSourceIntegrity],
]:
    plan, source_authorization = _authorization(1)
    _, validation_authorization = _authorization(2)

    def changed_result(
        *,
        run_id: str,
        authorization: LocalWebAssessmentAuthorization,
        started_at: datetime,
    ) -> LocalWebAssessmentResult:
        original = _result(
            run_id=run_id,
            plan=plan,
            authorization=authorization,
            started_at=started_at,
        )
        changed_issues = list(original.issues)
        issue_raw = changed_issues[0].model_dump(mode="json")
        issue_raw[field] = value
        if field == "cwe":
            issue_raw["issue_id"] = "web-issue:" + discovery_digest(
                "pajin.web-assessment.issue/v1",
                {
                    "check": issue_raw["check"],
                    "cwe": value,
                    "trials": issue_raw["trials"],
                },
            )
        changed_issues[0] = AssessmentIssue.model_validate(issue_raw)
        result_raw = original.model_dump(mode="json")
        result_raw["result_digest"] = ""
        result_raw["issues"] = [issue.model_dump(mode="json") for issue in changed_issues]
        result_raw["attack_paths"] = [
            path.model_dump(mode="json") for path in build_attack_paths(tuple(changed_issues))
        ]
        return LocalWebAssessmentResult.model_validate(result_raw)

    source_result = changed_result(
        run_id="run_20260914T030010Z_11111111",
        authorization=source_authorization,
        started_at=NOW + timedelta(seconds=10),
    )
    validation_result = changed_result(
        run_id="run_20260914T030030Z_22222222",
        authorization=validation_authorization,
        started_at=NOW + timedelta(seconds=30),
    )
    verified_source = _verified_source(
        plan=plan,
        authorization=source_authorization,
        result=source_result,
        index=1,
    )
    verified_validation = _verified_source(
        plan=plan,
        authorization=validation_authorization,
        result=validation_result,
        index=2,
    )
    source = local_web_assessment_run_reference(
        role="source",
        verified_source=verified_source,
    )
    validation = local_web_assessment_run_reference(
        role="validation",
        verified_source=verified_validation,
    )
    result = reconcile_local_web_assessment_runs(
        plan=plan,
        source=source,
        validation=validation,
        reconciled_at=NOW + timedelta(minutes=1),
    )
    return (
        source,
        validation,
        result,
        {
            source.run_id: verified_source,
            validation.run_id: verified_validation,
        },
    )
@dataclass(frozen=True, slots=True)
class _ExecutionBundle:
    backend: HostLoopbackBrowserWorkerBackend
    grant_consumption_store: WebAssessmentCapabilityGrantConsumptionStore
    source_action: SignedWebWorkerActionEvidence
    validation_action: SignedWebWorkerActionEvidence
    source_completion: WebWorkerCompletedActionAuthority
    validation_completion: WebWorkerCompletedActionAuthority
    source_gateway_completion: WebGatewayCompletedActionAuthority
    validation_gateway_completion: WebGatewayCompletedActionAuthority
    evidence: reporting.GovernedWebExecutionEvidence


class _ApprovalInputAuthority:
    def verify_action_approval(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> None:
        assert approval.mission_envelope == envelope
        assert approval.proposal == proposal
        assert approval.graph_decision == decision


def _key_bytes(role: WebWorkerRole, *, salt: int = 0) -> bytes:
    return bytes([list(WebWorkerRole).index(role) + 1 + salt]) * 32


def _worker_registry(
    *,
    salt: int = 0,
    not_after: datetime = ACTIVE_KEY_NOT_AFTER,
) -> WebWorkerTrustRegistry:
    keys = [
        WebWorkerVerificationKey(
            keyId=f"key:{salt}:{role.value}",
            role=role,
            publicKeyBase64url=web_worker_public_key_base64url(
                _key_bytes(role, salt=salt)
            ),
            state=WebWorkerKeyState.ACTIVE,
            notBefore=NOW - timedelta(days=1),
            notAfter=not_after,
        )
        for role in WebWorkerRole
    ]
    return WebWorkerTrustRegistry(
        trustDomain=f"pajin.web.reporting-test-{salt}",
        issuer=f"deployment:reporting-test:{salt}",
        keys=tuple(sorted(keys, key=lambda item: (item.role.value, item.key_id))),
    )


def _attestor(role: WebWorkerRole, *, salt: int = 0) -> WebWorkerAttestor:
    return WebWorkerAttestor.from_private_key_base64url(
        key_id=f"key:{salt}:{role.value}",
        role=role,
        trust_domain=f"pajin.web.reporting-test-{salt}",
        issuer=f"deployment:reporting-test:{salt}",
        private_key_base64url=web_worker_private_key_base64url(
            _key_bytes(role, salt=salt)
        ),
    )


def _target_identity_digest() -> str:
    return web_target_fingerprint_digest(
        origin=ORIGIN,
        product="OWASP Juice Shop",
        version=TARGET_VERSION,
        fingerprint_endpoint=FINGERPRINT_ENDPOINT,
        response_sha256=FINGERPRINT_RESPONSE_SHA256,
        adapter_implementation_digest=ADAPTER_IMPLEMENTATION_DIGEST,
        recipe_digest=RECIPE_DIGEST,
    )


def _synthetic_authorization(role: Literal["source", "validation"]) -> dict[str, str]:
    return {
        "permit_id": f"action-permit_{_digest(f'{role}-permit-id')}",
        "permit_digest": _digest(f"{role}-permit"),
        "approval_id": f"action-approval_{_digest(f'{role}-approval-id')}",
        "approval_digest": _digest(f"{role}-approval"),
        "receipt_id": f"action-approval-receipt_{_digest(f'{role}-receipt-id')}",
        "receipt_digest": _digest(f"{role}-receipt"),
        "request_id": f"gateway_web_{role}_1",
        "request_digest": _digest(f"{role}-gateway-request"),
    }


def _authorization_fields(
    role: Literal["source", "validation"],
    authorization: ActionApprovalAuthorization | None,
) -> dict[str, str]:
    if authorization is None:
        return _synthetic_authorization(role)
    return {
        "permit_id": authorization.action.permit.permit_id,
        "permit_digest": authorization.action.permit.permit_digest,
        "approval_id": authorization.approval.approval_id,
        "approval_digest": authorization.approval.approval_digest,
        "receipt_id": authorization.receipt.receipt_id,
        "receipt_digest": authorization.receipt.receipt_digest,
        "request_id": authorization.action.permit.request_id,
        "request_digest": authorization.action.permit.request_digest,
    }


def _worker_authority(
    *,
    role: Literal["source", "validation"],
    expected_run_id: str,
    authorization: ActionApprovalAuthorization | None,
    grant_receipt: WebAssessmentCapabilityGrantConsumptionReceipt,
) -> WebWorkerAuthorityBinding:
    fields = _authorization_fields(role, authorization)
    return WebWorkerAuthorityBinding(
        campaignId=CAMPAIGN_ID,
        campaignDigest=CAMPAIGN_DIGEST,
        capabilityId=CAPABILITY_ID,
        capabilityVersion=CAPABILITY_VERSION,
        capabilityDigest=CAPABILITY_DEFINITION_DIGEST,
        capabilityGrantId=f"grant:web:governed:{role}:1",
        capabilityGrantDigest=_digest(f"{role}-grant"),
        capabilityGrantConsumptionReceiptId=grant_receipt.receipt_id,
        capabilityGrantConsumptionReceiptDigest=grant_receipt.receipt_digest,
        adapterDigest=ADAPTER_DIGEST,
        adapterImplementationDigest=ADAPTER_IMPLEMENTATION_DIGEST,
        recipeDigest=RECIPE_DIGEST,
        accountReceiptDigest=ACCOUNT_RECEIPT_DIGEST,
        targetOrigin=ORIGIN,
        targetProduct="OWASP Juice Shop",
        targetVersion=TARGET_VERSION,
        targetFingerprintEndpoint=FINGERPRINT_ENDPOINT,
        expectedTargetResponseSha256=FINGERPRINT_RESPONSE_SHA256,
        expectedTargetFingerprintDigest=_target_identity_digest(),
        requestId=fields["request_id"],
        requestDigest=fields["request_digest"],
        actionPermitId=fields["permit_id"],
        actionPermitDigest=fields["permit_digest"],
        approvalId=fields["approval_id"],
        approvalDigest=fields["approval_digest"],
        approvalReceiptId=fields["receipt_id"],
        approvalReceiptDigest=fields["receipt_digest"],
        dispatchBindingDigest=_digest(f"{role}-dispatch-binding"),
        expectedRunId=expected_run_id,
    )


def _signed_action(
    *,
    role: Literal["source", "validation"],
    run: LocalWebAssessmentRunReference,
    authorization: ActionApprovalAuthorization | None,
    grant_receipt: WebAssessmentCapabilityGrantConsumptionReceipt,
    salt: int = 0,
) -> SignedWebWorkerActionEvidence:
    authority = _worker_authority(
        role=role,
        expected_run_id=run.run_id,
        authorization=authorization,
        grant_receipt=grant_receipt,
    )
    observer_role: Literal[
        WebWorkerRole.SOURCE_TARGET_OBSERVER,
        WebWorkerRole.VALIDATION_TARGET_OBSERVER,
    ] = (
        WebWorkerRole.SOURCE_TARGET_OBSERVER
        if role == "source"
        else WebWorkerRole.VALIDATION_TARGET_OBSERVER
    )
    executor_role: Literal[
        WebWorkerRole.SOURCE_EXECUTOR,
        WebWorkerRole.VALIDATION_EXECUTOR,
    ] = (
        WebWorkerRole.SOURCE_EXECUTOR
        if role == "source"
        else WebWorkerRole.VALIDATION_EXECUTOR
    )
    offset = 0 if role == "source" else 2
    target = _attestor(observer_role, salt=salt).sign_target(
        WebTargetIdentityStatement(
            trustDomain=f"pajin.web.reporting-test-{salt}",
            issuer=f"deployment:reporting-test:{salt}",
            authority=authority,
            role=observer_role,
            executionId=f"execution:{role}:target:{salt}",
            targetProduct="OWASP Juice Shop",
            targetVersion=TARGET_VERSION,
            fingerprintEndpoint=FINGERPRINT_ENDPOINT,
            observedTargetFingerprintDigest=_target_identity_digest(),
            responseSha256=FINGERPRINT_RESPONSE_SHA256,
            responseBytes=len(FINGERPRINT_BODY),
            processId=101 + offset,
            startedAt=run.result.started_at - timedelta(seconds=2),
            finishedAt=run.result.started_at - timedelta(seconds=1),
            issuedAt=run.result.started_at - timedelta(seconds=1),
        )
    )
    execution = _attestor(executor_role, salt=salt).sign_execution(
        WebExecutionStatement(
            trustDomain=f"pajin.web.reporting-test-{salt}",
            issuer=f"deployment:reporting-test:{salt}",
            authority=authority,
            role=executor_role,
            executionId=f"execution:{role}:executor:{salt}",
            targetIdentityAttestationDigest=target.digest,
            runId=run.run_id,
            runRootDigest=run.root_digest,
            resultDigest=run.result_digest,
            processId=102 + offset,
            startedAt=run.result.started_at,
            finishedAt=run.result.finished_at,
            issuedAt=run.result.finished_at + timedelta(seconds=1),
        )
    )
    return SignedWebWorkerActionEvidence(
        targetIdentity=target,
        executionAttestation=execution,
    )


def _grant_receipt(
    *,
    role: Literal["source", "validation"],
    authorization: ActionApprovalAuthorization | None,
    grant_authority_digest: str,
) -> tuple[
    WebAssessmentCapabilityGrantReservation,
    WebAssessmentCapabilityGrantConsumptionReceipt,
]:
    fields = _authorization_fields(role, authorization)
    reservation = WebAssessmentCapabilityGrantReservation(
        campaignId=CAMPAIGN_ID,
        grantAuthorityDigest=grant_authority_digest,
        capabilityGrantId=f"grant:web:governed:{role}:1",
        capabilityGrantDigest=_digest(f"{role}-grant"),
        requestId=fields["request_id"],
        requestDigest=fields["request_digest"],
        permitId=fields["permit_id"],
        permitDigest=fields["permit_digest"],
        approvalReceiptId=fields["receipt_id"],
        approvalReceiptDigest=fields["receipt_digest"],
        reservedAt=NOW - timedelta(seconds=1),
    )
    return reservation, WebAssessmentCapabilityGrantConsumptionReceipt(
        reservationId=reservation.reservation_id,
        reservationDigest=reservation.reservation_digest,
        campaignId=CAMPAIGN_ID,
        grantAuthorityDigest=grant_authority_digest,
        capabilityGrantId=reservation.capability_grant_id,
        capabilityGrantDigest=reservation.capability_grant_digest,
        requestId=reservation.request_id,
        requestDigest=reservation.request_digest,
        permitId=reservation.permit_id,
        permitDigest=reservation.permit_digest,
        approvalReceiptId=reservation.approval_receipt_id,
        approvalReceiptDigest=reservation.approval_receipt_digest,
        consumedAt=NOW,
    )


def _grant_consumption_store(
    *,
    source_authorization: ActionApprovalAuthorization | None,
    validation_authorization: ActionApprovalAuthorization | None,
) -> tuple[
    WebAssessmentCapabilityGrantConsumptionStore,
    WebAssessmentCapabilityGrantConsumptionReceipt,
    WebAssessmentCapabilityGrantConsumptionReceipt,
]:
    root = Path(tempfile.mkdtemp(prefix="pajin-governed-reporting-test-")).resolve()
    store = WebAssessmentCapabilityGrantConsumptionStore(
        root / "grant-consumptions.sqlite3",
        campaign_id=CAMPAIGN_ID,
    )
    grant_authority_digest = _digest("web-grant-authority")
    source_reservation, source_receipt = _grant_receipt(
        role="source",
        authorization=source_authorization,
        grant_authority_digest=grant_authority_digest,
    )
    validation_reservation, validation_receipt = _grant_receipt(
        role="validation",
        authorization=validation_authorization,
        grant_authority_digest=grant_authority_digest,
    )
    path = store._path
    with sqlite3.connect(path) as connection:
        for reservation in (source_reservation, validation_reservation):
            connection.execute(
                """
                INSERT INTO web_capability_grant_reservations (
                    reservation_id, reservation_digest, campaign_id,
                    capability_grant_id, request_id, permit_id,
                    approval_receipt_id, reservation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    reservation.reservation_id,
                    reservation.reservation_digest,
                    reservation.campaign_id,
                    reservation.capability_grant_id,
                    reservation.request_id,
                    reservation.permit_id,
                    reservation.approval_receipt_id,
                    reservation.model_dump_json(by_alias=True),
                ),
            )
        for receipt in (source_receipt, validation_receipt):
            connection.execute(
                """
                INSERT INTO web_capability_grant_consumptions (
                    receipt_id, receipt_digest, reservation_id, campaign_id,
                    capability_grant_id, request_id, permit_id,
                    approval_receipt_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.receipt_id,
                    receipt.receipt_digest,
                    receipt.reservation_id,
                    receipt.campaign_id,
                    receipt.capability_grant_id,
                    receipt.request_id,
                    receipt.permit_id,
                    receipt.approval_receipt_id,
                    receipt.model_dump_json(by_alias=True),
                ),
            )
    return store, source_receipt, validation_receipt


def _register_completed_action_fixture(
    *,
    backend: HostLoopbackBrowserWorkerBackend,
    action: SignedWebWorkerActionEvidence,
    completed_at: datetime,
) -> WebWorkerCompletedActionAuthority:
    execution = action.execution_attestation
    target = action.target_identity
    record = WebWorkerCompletedActionRecord(
        workerTrustRegistryDigest=backend.trust_registry.digest,
        role=execution.statement.role,
        authority=execution.statement.authority,
        gatewayLaunchId=f"web-gateway-launch:{execution.statement.execution_id}",
        gatewayAuditRunId=(
            "run_20260914T025900Z_aaaaaaaa"
            if execution.statement.role is WebWorkerRole.SOURCE_EXECUTOR
            else "run_20260914T025930Z_bbbbbbbb"
        ),
        gatewayExecutionId=execution.statement.execution_id,
        workerExecutionId=execution.statement.execution_id,
        observerExecutionId=target.statement.execution_id,
        observerProcessId=target.statement.process_id,
        executorProcessId=execution.statement.process_id,
        observerKeyId=target.key_id,
        executorKeyId=execution.key_id,
        targetIdentityAttestationDigest=target.digest,
        executionAttestationDigest=execution.digest,
        workerActionEvidenceDigest=action.digest,
        targetIdentityDigest=execution.statement.authority.expected_target_fingerprint_digest,
        runId=execution.statement.run_id,
        runRootDigest=execution.statement.run_root_digest,
        resultDigest=execution.statement.result_digest,
        workerResultDigest=_digest(f"worker-result:{execution.statement.execution_id}"),
        completedAt=completed_at,
    )
    factory_token = cast(
        object,
        object.__getattribute__(
            backend,
            "_HostLoopbackBrowserWorkerBackend__completion_factory_token",
        ),
    )
    authority = WebWorkerCompletedActionAuthority(
        _backend=backend,
        _factory_token=factory_token,
        _record=record,
        _action_evidence=action,
    )
    backend._completed_actions[record.gateway_execution_id] = authority
    return authority


def _gateway_completion_fixture(
    *,
    role: Literal["source", "validation"],
    backend_completion: WebWorkerCompletedActionAuthority,
) -> WebGatewayCompletedActionAuthority:
    completion = backend_completion.completion
    request_id = completion.authority.request_id
    gateway_root = Path(
        tempfile.mkdtemp(prefix=f"pajin-governed-{role}-gateway-test-")
    ).resolve()
    gateway_store = RunStore.create(
        gateway_root,
        f"web-{role}-gateway",
        run_id=completion.gateway_audit_run_id,
    )
    gateway_store.append_event(
        "web-gateway.fixture-completed",
        {"role": role, "requestId": request_id},
        occurred_at=completion.completed_at,
    )
    gateway_store.write_json(
        "gateway-fixture.json",
        {"role": role, "requestId": request_id},
    )
    gateway_store.seal()
    receipt = WebGatewayCompletionReceipt(
        role=role,
        authority=completion.authority,
        dispatchBindingDigest=completion.authority.dispatch_binding_digest,
        requestId=request_id,
        workerExecutionId=completion.worker_execution_id,
        gatewayLaunchId=completion.gateway_launch_id,
        gatewayAuditRunId=completion.gateway_audit_run_id,
        gatewayAuditRootDigest=_digest(f"{role}-gateway-pre-receipt-root"),
        gatewayEventHeadDigest=_digest(f"{role}-gateway-pre-receipt-head"),
        gatewayEvidenceReference=f"evidence/{request_id}.json",
        gatewayEvidenceDigest=_digest(f"{role}-gateway-evidence"),
        gatewayRequestReservationReference=f"requests/{request_id}.json",
        gatewayRequestReservationDigest=_digest(f"{role}-gateway-request-reservation"),
        backendCompletionDigest=completion.completion_digest,
        workerResultDigest=completion.worker_result_digest,
        toolResultDigest=_digest(f"{role}-gateway-tool-result"),
        policyDecisionDigest=_digest("gateway-policy-decision"),
        gatewayOutcomeDigest=_digest(f"{role}-gateway-outcome"),
        completedAt=completion.completed_at + timedelta(seconds=1),
    )
    return WebGatewayCompletedActionAuthority(
        gateway=object(),
        token=object(),
        receipt=receipt,
        receipt_reference=f"gateway-completions/{receipt.receipt_digest}.json",
        backend_completion=backend_completion,
        final_root_digest=_digest(f"{role}-gateway-final-root"),
        final_event_head=_digest(f"{role}-gateway-final-head"),
        run_path=gateway_store.path,
    )


def _execution_bundle(
    source: LocalWebAssessmentRunReference,
    validation: LocalWebAssessmentRunReference,
    *,
    source_authorization: ActionApprovalAuthorization | None = None,
    validation_authorization: ActionApprovalAuthorization | None = None,
    registry: WebWorkerTrustRegistry | None = None,
    salt: int = 0,
) -> _ExecutionBundle:
    selected_registry = registry or _worker_registry(salt=salt)
    grant_store, source_grant_receipt, validation_grant_receipt = (
        _grant_consumption_store(
            source_authorization=source_authorization,
            validation_authorization=validation_authorization,
        )
    )
    source_action = _signed_action(
        role="source",
        run=source,
        authorization=source_authorization,
        grant_receipt=source_grant_receipt,
        salt=salt,
    )
    validation_action = _signed_action(
        role="validation",
        run=validation,
        authorization=validation_authorization,
        grant_receipt=validation_grant_receipt,
        salt=salt,
    )
    source_authority = source_action.execution_attestation.statement.authority
    validation_authority = validation_action.execution_attestation.statement.authority
    backend = HostLoopbackBrowserWorkerBackend.production(
        output_root=Path("/synthetic/governed-worker-output"),
        trust_registry=selected_registry,
    )
    source_completion = _register_completed_action_fixture(
        backend=backend,
        action=source_action,
        completed_at=source.result.finished_at + timedelta(seconds=2),
    )
    validation_completion = _register_completed_action_fixture(
        backend=backend,
        action=validation_action,
        completed_at=validation.result.finished_at + timedelta(seconds=2),
    )
    source_gateway_completion = _gateway_completion_fixture(
        role="source",
        backend_completion=source_completion,
    )
    validation_gateway_completion = _gateway_completion_fixture(
        role="validation",
        backend_completion=validation_completion,
    )
    source_gateway_receipt = source_gateway_completion.receipt
    validation_gateway_receipt = validation_gateway_completion.receipt
    evidence = reporting.GovernedWebExecutionEvidence(
        campaignId=CAMPAIGN_ID,
        campaignManifestDigest=CAMPAIGN_DIGEST,
        sourceCapabilityGrantId=source_authority.capability_grant_id,
        sourceCapabilityGrantDigest=source_authority.capability_grant_digest,
        sourceCapabilityGrantConsumptionReceiptId=source_grant_receipt.receipt_id,
        sourceCapabilityGrantConsumptionReceiptDigest=source_grant_receipt.receipt_digest,
        validationCapabilityGrantId=validation_authority.capability_grant_id,
        validationCapabilityGrantDigest=validation_authority.capability_grant_digest,
        validationCapabilityGrantConsumptionReceiptId=validation_grant_receipt.receipt_id,
        validationCapabilityGrantConsumptionReceiptDigest=(
            validation_grant_receipt.receipt_digest
        ),
        capabilityGrantAuthorityDigest=source_grant_receipt.grant_authority_digest,
        capabilityId=CAPABILITY_ID,
        capabilityVersion=CAPABILITY_VERSION,
        capabilityDigest=CAPABILITY_DEFINITION_DIGEST,
        adapterRef="juice-shop-local/v1",
        adapterDigest=ADAPTER_DIGEST,
        accountReceiptDigest=ACCOUNT_RECEIPT_DIGEST,
        workerTrustRegistryDigest=selected_registry.digest,
        executionVerifierDigest=reporting.governed_web_execution_verifier_digest(
            selected_registry
        ),
        sourceActionPermitId=source_authority.action_permit_id,
        sourceActionPermitDigest=source_authority.action_permit_digest,
        validationActionPermitId=validation_authority.action_permit_id,
        validationActionPermitDigest=validation_authority.action_permit_digest,
        sourceApprovalId=source_authority.approval_id,
        sourceApprovalDigest=source_authority.approval_digest,
        validationApprovalId=validation_authority.approval_id,
        validationApprovalDigest=validation_authority.approval_digest,
        sourceApprovalReceiptId=source_authority.approval_receipt_id,
        sourceApprovalReceiptDigest=source_authority.approval_receipt_digest,
        validationApprovalReceiptId=validation_authority.approval_receipt_id,
        validationApprovalReceiptDigest=validation_authority.approval_receipt_digest,
        sourceGatewayRequestId=source_authority.request_id,
        sourceGatewayRequestDigest=source_authority.request_digest,
        validationGatewayRequestId=validation_authority.request_id,
        validationGatewayRequestDigest=validation_authority.request_digest,
        sourceGatewayAuditRunId=source_gateway_receipt.gateway_audit_run_id,
        validationGatewayAuditRunId=validation_gateway_receipt.gateway_audit_run_id,
        sourceGatewayAuditPreReceiptRootDigest=(
            source_gateway_receipt.gateway_audit_root_digest
        ),
        validationGatewayAuditPreReceiptRootDigest=(
            validation_gateway_receipt.gateway_audit_root_digest
        ),
        sourceGatewayAuditPreReceiptEventHeadDigest=(
            source_gateway_receipt.gateway_event_head_digest
        ),
        validationGatewayAuditPreReceiptEventHeadDigest=(
            validation_gateway_receipt.gateway_event_head_digest
        ),
        sourceGatewayAuditFinalRootDigest=source_gateway_completion.final_root_digest,
        validationGatewayAuditFinalRootDigest=validation_gateway_completion.final_root_digest,
        sourceGatewayAuditFinalEventHeadDigest=source_gateway_completion.final_event_head,
        validationGatewayAuditFinalEventHeadDigest=validation_gateway_completion.final_event_head,
        sourceGatewayCompletionReceiptId=source_gateway_receipt.receipt_id,
        validationGatewayCompletionReceiptId=validation_gateway_receipt.receipt_id,
        sourceGatewayCompletionReceiptDigest=source_gateway_receipt.receipt_digest,
        validationGatewayCompletionReceiptDigest=validation_gateway_receipt.receipt_digest,
        sourceGatewayCompletionReceiptReference=source_gateway_completion.receipt_reference,
        validationGatewayCompletionReceiptReference=validation_gateway_completion.receipt_reference,
        sourceGatewayCompletionAuthorityDigest=source_gateway_completion.authority_digest,
        validationGatewayCompletionAuthorityDigest=validation_gateway_completion.authority_digest,
        sourceGatewayLaunchId=source_gateway_receipt.gateway_launch_id,
        validationGatewayLaunchId=validation_gateway_receipt.gateway_launch_id,
        sourceGatewayEvidenceReference=source_gateway_receipt.gateway_evidence_reference,
        validationGatewayEvidenceReference=validation_gateway_receipt.gateway_evidence_reference,
        sourceGatewayEvidenceDigest=source_gateway_receipt.gateway_evidence_digest,
        validationGatewayEvidenceDigest=validation_gateway_receipt.gateway_evidence_digest,
        sourceGatewayRequestReservationReference=(
            source_gateway_receipt.gateway_request_reservation_reference
        ),
        validationGatewayRequestReservationReference=(
            validation_gateway_receipt.gateway_request_reservation_reference
        ),
        sourceGatewayRequestReservationDigest=(
            source_gateway_receipt.gateway_request_reservation_digest
        ),
        validationGatewayRequestReservationDigest=(
            validation_gateway_receipt.gateway_request_reservation_digest
        ),
        sourceGatewayWorkerResultDigest=source_gateway_receipt.worker_result_digest,
        validationGatewayWorkerResultDigest=validation_gateway_receipt.worker_result_digest,
        sourceGatewayToolResultDigest=source_gateway_receipt.tool_result_digest,
        validationGatewayToolResultDigest=validation_gateway_receipt.tool_result_digest,
        sourceGatewayPolicyDecisionDigest=source_gateway_receipt.policy_decision_digest,
        validationGatewayPolicyDecisionDigest=validation_gateway_receipt.policy_decision_digest,
        sourceGatewayOutcomeDigest=source_gateway_receipt.gateway_outcome_digest,
        validationGatewayOutcomeDigest=validation_gateway_receipt.gateway_outcome_digest,
        targetOrigin=ORIGIN,
        targetIdentityDigest=_target_identity_digest(),
        sourceAuthorizationId=source.authorization_id,
        validationAuthorizationId=validation.authorization_id,
        sourceRunId=source.run_id,
        sourceRootDigest=source.root_digest,
        sourceResultDigest=source.result_digest,
        validationRunId=validation.run_id,
        validationRootDigest=validation.root_digest,
        validationResultDigest=validation.result_digest,
        sourceExecutorProcessId=source_action.execution_attestation.statement.process_id,
        validationExecutorProcessId=(
            validation_action.execution_attestation.statement.process_id
        ),
        sourceObserverProcessId=source_action.target_identity.statement.process_id,
        validationObserverProcessId=validation_action.target_identity.statement.process_id,
        sourceExecutorKeyId=source_action.execution_attestation.key_id,
        validationExecutorKeyId=validation_action.execution_attestation.key_id,
        sourceExecutorExecutionId=(
            source_action.execution_attestation.statement.execution_id
        ),
        validationExecutorExecutionId=(
            validation_action.execution_attestation.statement.execution_id
        ),
        sourceExecutionAttestationDigest=source_action.execution_attestation.digest,
        validationExecutionAttestationDigest=(
            validation_action.execution_attestation.digest
        ),
        sourceObserverKeyId=source_action.target_identity.key_id,
        validationObserverKeyId=validation_action.target_identity.key_id,
        sourceObserverExecutionId=source_action.target_identity.statement.execution_id,
        validationObserverExecutionId=(
            validation_action.target_identity.statement.execution_id
        ),
        sourceTargetAttestationDigest=source_action.target_identity.digest,
        validationTargetAttestationDigest=validation_action.target_identity.digest,
        sourceWorkerActionEvidenceDigest=source_action.digest,
        validationWorkerActionEvidenceDigest=validation_action.digest,
        sourceWorkerCompletionDigest=source_completion.completion_digest,
        validationWorkerCompletionDigest=validation_completion.completion_digest,
        sourceCompletedAt=source.result.finished_at,
        validationCompletedAt=validation.result.finished_at,
        sourceGatewayCompletedAt=source_gateway_receipt.completed_at,
        validationGatewayCompletedAt=validation_gateway_receipt.completed_at,
        completedAt=max(
            source_gateway_receipt.completed_at,
            validation_gateway_receipt.completed_at,
        ),
    )
    return _ExecutionBundle(
        backend=backend,
        grant_consumption_store=grant_store,
        source_action=source_action,
        validation_action=validation_action,
        source_completion=source_completion,
        validation_completion=validation_completion,
        source_gateway_completion=source_gateway_completion,
        validation_gateway_completion=validation_gateway_completion,
        evidence=evidence,
    )


def _load_runs(
    monkeypatch: pytest.MonkeyPatch,
    verified: dict[str, VerifiedLocalWebAssessmentSourceIntegrity],
) -> None:
    def load(
        _path: Path,
        *,
        expected_run_id: str,
        expected_root_digest: str,
    ) -> VerifiedLocalWebAssessmentSourceIntegrity:
        selected = verified[expected_run_id]
        assert selected.verification.root_digest == expected_root_digest
        return selected

    monkeypatch.setattr(
        reporting,
        "load_verified_local_web_assessment_source_integrity",
        load,
    )
    monkeypatch.setattr(
        reporting,
        "_system_utc_now",
        lambda: NOW + timedelta(minutes=3),
    )
    monkeypatch.setattr(
        reporting,
        "verify_consumed_web_gateway_completed_action_pair",
        lambda **_kwargs: None,
    )


def _verifier(bundle: _ExecutionBundle) -> reporting.GovernedWebExecutionVerifierBinding:
    def consume_fixture(
        *,
        expected_backend: HostLoopbackBrowserWorkerBackend,
        source: WebGatewayCompletedActionAuthority,
        validation: WebGatewayCompletedActionAuthority,
    ) -> tuple[WebGatewayCompletedActionAuthority, WebGatewayCompletedActionAuthority]:
        if (
            expected_backend is not bundle.backend
            or source is not bundle.source_gateway_completion
            or validation is not bundle.validation_gateway_completion
        ):
            raise ValueError("foreign reporting Gateway fixture")
        bundle.backend.consume_completed_action_authorities(
            source=source.backend_completion,
            validation=validation.backend_completion,
        )
        return source, validation

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            reporting,
            "consume_web_gateway_completed_action_pair",
            consume_fixture,
        )
        return reporting.create_governed_web_execution_verifier_binding(
            worker_backend=bundle.backend,
            grant_consumption_store=bundle.grant_consumption_store,
            source_gateway_completion=bundle.source_gateway_completion,
            validation_gateway_completion=bundle.validation_gateway_completion,
        )


def _promotion(
    monkeypatch: pytest.MonkeyPatch,
    *,
    source_authorization: ActionApprovalAuthorization | None = None,
    validation_authorization: ActionApprovalAuthorization | None = None,
) -> reporting.GovernedWebPromotionAuthority:
    source, validation, result, verified = _campaign_result()
    _load_runs(monkeypatch, verified)
    bundle = _execution_bundle(
        source,
        validation,
        source_authorization=source_authorization,
        validation_authorization=validation_authorization,
    )
    return reporting.promote_governed_web_findings(
        reconciliation=result,
        execution_evidence=bundle.evidence,
        verifier=_verifier(bundle),
        source_run_path=Path("/synthetic/source"),
        validation_run_path=Path("/synthetic/validation"),
        promoted_at=NOW + timedelta(minutes=4),
    )


def test_execution_evidence_allows_equal_semantic_policy_decision_digests() -> None:
    source, validation, _result, _verified = _campaign_result()
    evidence = _execution_bundle(source, validation).evidence
    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["evidenceDigest"] = ""
    raw["validationGatewayPolicyDecisionDigest"] = raw[
        "sourceGatewayPolicyDecisionDigest"
    ]

    decoded = reporting.GovernedWebExecutionEvidence.model_validate(raw)

    assert (
        decoded.validation_gateway_policy_decision_digest
        == decoded.source_gateway_policy_decision_digest
    )

    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["evidenceDigest"] = ""
    raw["validationGatewayOutcomeDigest"] = raw["sourceGatewayOutcomeDigest"]
    with pytest.raises(ValidationError, match="Gateway outcome digests"):
        reporting.GovernedWebExecutionEvidence.model_validate(raw)


def test_promotion_time_advances_to_trusted_verification_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, validation, result, verified = _campaign_result()
    _load_runs(monkeypatch, verified)
    bundle = _execution_bundle(source, validation)
    trusted_verification_time = NOW + timedelta(minutes=5)
    monkeypatch.setattr(
        reporting,
        "_system_utc_now",
        lambda: trusted_verification_time,
    )

    authority = reporting.promote_governed_web_findings(
        reconciliation=result,
        execution_evidence=bundle.evidence,
        verifier=_verifier(bundle),
        source_run_path=Path("/synthetic/source"),
        validation_run_path=Path("/synthetic/validation"),
        promoted_at=NOW + timedelta(minutes=4),
    )

    assert authority.promotion.execution_verification.verified_at == trusted_verification_time
    assert authority.promotion.promoted_at == trusted_verification_time


def test_promotion_requires_distinct_execution_and_target_attestations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, validation, result, verified = _campaign_result()
    _load_runs(monkeypatch, verified)
    bundle = _execution_bundle(source, validation)
    evidence = bundle.evidence
    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["evidenceDigest"] = ""
    raw["validationExecutorProcessId"] = raw["sourceExecutorProcessId"]
    with pytest.raises(ValidationError, match="executor process IDs"):
        reporting.GovernedWebExecutionEvidence.model_validate(raw)

    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["evidenceDigest"] = ""
    raw["validationTargetAttestationDigest"] = raw["sourceTargetAttestationDigest"]
    with pytest.raises(ValidationError, match="target attestations"):
        reporting.GovernedWebExecutionEvidence.model_validate(raw)

    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["evidenceDigest"] = ""
    raw["sourceExecutorSignatureVerified"] = False
    with pytest.raises(ValidationError, match="signature verification"):
        reporting.GovernedWebExecutionEvidence.model_validate(raw)

    authority = reporting.promote_governed_web_findings(
        reconciliation=result,
        execution_evidence=evidence,
        verifier=_verifier(bundle),
        source_run_path=Path("/synthetic/source"),
        validation_run_path=Path("/synthetic/validation"),
        promoted_at=NOW + timedelta(minutes=4),
    )
    promotion = authority.promotion
    assert len(promotion.findings) == 3
    assert all(finding.validated for finding in promotion.findings)
    assert len(promotion.attack_paths) == 2
    assert promotion.execution_verification.evidence_digest == evidence.evidence_digest

    class _FakeVerifier:
        verifier_id = reporting.GOVERNED_WEB_EXECUTION_VERIFIER_ID
        verifier_digest = evidence.execution_verifier_digest

        def verify(
            self,
            candidate: reporting.GovernedWebExecutionEvidence,
            *,
            source: LocalWebAssessmentRunReference,
            validation: LocalWebAssessmentRunReference,
        ) -> reporting.GovernedWebExecutionVerification:
            return reporting.GovernedWebExecutionVerification(
                verifierId=self.verifier_id,
                verifierDigest=self.verifier_digest,
                evidenceDigest=candidate.evidence_digest,
                verifiedAt=NOW + timedelta(minutes=3),
            )

    with pytest.raises(TypeError, match="code-owned execution verifier"):
        reporting.promote_governed_web_findings(
            reconciliation=result,
            execution_evidence=evidence,
            verifier=_FakeVerifier(),  # type: ignore[arg-type]
            source_run_path=Path("/synthetic/source"),
            validation_run_path=Path("/synthetic/validation"),
            promoted_at=NOW + timedelta(minutes=4),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("potential_impact", "caller-selected potential impact"),
        ("remediation", "caller-selected remediation"),
    ],
)
def test_promotion_rejects_equal_noncanonical_issue_metadata(
    monkeypatch: pytest.MonkeyPatch,
    field: Literal["cwe", "severity", "potential_impact", "remediation"],
    value: str,
) -> None:
    source, validation, result, verified = _campaign_result_with_issue_field(
        field=field,
        value=value,
    )
    _load_runs(monkeypatch, verified)
    bundle = _execution_bundle(source, validation)

    with pytest.raises(ValueError, match="code-owned diagnostic"):
        reporting.promote_governed_web_findings(
            reconciliation=result,
            execution_evidence=bundle.evidence,
            verifier=_verifier(bundle),
            source_run_path=Path("/synthetic/source"),
            validation_run_path=Path("/synthetic/validation"),
            promoted_at=NOW + timedelta(minutes=4),
        )


@pytest.mark.parametrize(("field", "value"), [("cwe", "CWE-90"), ("severity", "medium")])
def test_issue_match_rejects_equal_noncanonical_cwe_or_severity(
    field: Literal["cwe", "severity"],
    value: str,
) -> None:
    issue = _issue("sql-login", evidence_ids=tuple(item.evidence_id for item in _requests()[:6]))
    raw = issue.model_dump(mode="json")
    raw[field] = value
    if field == "cwe":
        raw["issue_id"] = "web-issue:" + discovery_digest(
            "pajin.web-assessment.issue/v1",
            {
                "check": raw["check"],
                "cwe": value,
                "trials": raw["trials"],
            },
        )
    changed = AssessmentIssue.model_validate(raw)

    with pytest.raises(ValueError, match="code-owned diagnostic"):
        reporting._require_exact_issue_match(changed, changed.model_copy(deep=True))


@pytest.mark.parametrize("mutation", ["missing", "unknown", "mixed-negative"])
def test_attack_path_promotion_rejects_unlinked_or_negative_diagnostic_stage(
    monkeypatch: pytest.MonkeyPatch,
    mutation: Literal["missing", "unknown", "mixed-negative"],
) -> None:
    _, _, reconciliation, _ = _campaign_result()
    promotion = _promotion(monkeypatch)
    source_result = reconciliation.source.result
    validation_result = reconciliation.validation.result
    source_path = source_result.attack_paths[0]
    validation_path = validation_result.attack_paths[0]
    source_stages = list(source_path.stages)
    validation_stages = list(validation_path.stages)
    diagnostic_index = next(
        index for index, stage in enumerate(source_stages) if stage.state != "observed"
    )
    if mutation == "missing":
        source_stages[diagnostic_index] = source_stages[diagnostic_index].model_copy(
            update={"issue_id": None}
        )
        validation_stages[diagnostic_index] = validation_stages[
            diagnostic_index
        ].model_copy(update={"issue_id": None})
    elif mutation == "unknown":
        unknown_id = "web-issue:" + ("f" * 64)
        source_stages[diagnostic_index] = source_stages[diagnostic_index].model_copy(
            update={"issue_id": unknown_id}
        )
        validation_stages[diagnostic_index] = validation_stages[
            diagnostic_index
        ].model_copy(update={"issue_id": unknown_id})
    else:
        source_issues = list(source_result.issues)
        validation_issues = list(validation_result.issues)
        issue_id = source_stages[diagnostic_index].issue_id
        source_issue_index = next(
            index for index, issue in enumerate(source_issues) if issue.issue_id == issue_id
        )
        validation_issue_index = next(
            index
            for index, issue in enumerate(validation_issues)
            if issue.check == source_issues[source_issue_index].check
        )
        source_issues[source_issue_index] = source_issues[source_issue_index].model_copy(
            update={"status": "not-reproduced"}
        )
        validation_issues[validation_issue_index] = validation_issues[
            validation_issue_index
        ].model_copy(update={"status": "not-reproduced"})
        source_result = source_result.model_copy(update={"issues": tuple(source_issues)})
        validation_result = validation_result.model_copy(
            update={"issues": tuple(validation_issues)}
        )
    source_paths = list(source_result.attack_paths)
    validation_paths = list(validation_result.attack_paths)
    source_paths[0] = source_path.model_copy(update={"stages": tuple(source_stages)})
    validation_paths[0] = validation_path.model_copy(
        update={"stages": tuple(validation_stages)}
    )
    source_result = source_result.model_copy(update={"attack_paths": tuple(source_paths)})
    validation_result = validation_result.model_copy(
        update={"attack_paths": tuple(validation_paths)}
    )
    changed = reconciliation.model_copy(
        update={
            "source": reconciliation.source.model_copy(update={"result": source_result}),
            "validation": reconciliation.validation.model_copy(
                update={"result": validation_result}
            ),
        }
    )

    paths = reporting._derive_attack_paths(changed, promotion.findings)

    assert len(paths) == 1
    assert all(item.title != source_path.title for item in paths)


def test_attack_path_promotion_preserves_exact_observed_context_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, reconciliation, _ = _campaign_result()
    promotion = _promotion(monkeypatch)

    assert len(promotion.attack_paths) == 2
    assert any(
        stage.state == "observed" and stage.issue_id is None
        for path in reconciliation.source.result.attack_paths
        for stage in path.stages
    )


def test_verifier_factory_rejects_receipt_tamper_foreign_backend_and_time_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, validation, result, verified = _campaign_result()
    _load_runs(monkeypatch, verified)
    bundle = _execution_bundle(source, validation)

    tampered = bundle.evidence.model_dump(mode="json", by_alias=True)
    tampered["evidenceDigest"] = ""
    tampered["sourceApprovalReceiptId"] = (
        f"action-approval-receipt_{_digest('forged-receipt')}"
    )
    tampered_evidence = reporting.GovernedWebExecutionEvidence.model_validate(tampered)
    with pytest.raises(ValueError, match="receipt differs"):
        reporting.promote_governed_web_findings(
            reconciliation=result,
            execution_evidence=tampered_evidence,
            verifier=_verifier(bundle),
            source_run_path=Path("/synthetic/source"),
            validation_run_path=Path("/synthetic/validation"),
            promoted_at=NOW + timedelta(minutes=4),
        )

    foreign_backend = HostLoopbackBrowserWorkerBackend.production(
        output_root=Path("/synthetic/foreign-worker-output"),
        trust_registry=_worker_registry(salt=10),
    )
    foreign_bundle = _execution_bundle(source, validation, salt=20)
    with pytest.raises((TypeError, ValueError), match=r"Gateway|foreign|independent"):
        reporting.create_governed_web_execution_verifier_binding(
            worker_backend=foreign_backend,
            grant_consumption_store=foreign_bundle.grant_consumption_store,
            source_gateway_completion=foreign_bundle.source_gateway_completion,
            validation_gateway_completion=foreign_bundle.validation_gateway_completion,
        )
    with pytest.raises((TypeError, ValueError), match="Gateway"):
        reporting.create_governed_web_execution_verifier_binding(
            worker_backend=bundle.backend,
            grant_consumption_store=bundle.grant_consumption_store,
            source_gateway_completion=bundle.source_completion,  # type: ignore[arg-type]
            validation_gateway_completion=bundle.validation_completion,  # type: ignore[arg-type]
        )

    parameters = inspect.signature(
        reporting.create_governed_web_execution_verifier_binding
    ).parameters
    assert "registry" not in parameters
    assert "clock" not in parameters
    assert "verification_time" not in parameters
    with pytest.raises(TypeError, match="code-owned factory"):
        reporting.GovernedWebExecutionVerifierBinding(
            worker_backend=bundle.backend,
            grant_consumption_store=bundle.grant_consumption_store,
            source_gateway_completion=bundle.source_gateway_completion,
            validation_gateway_completion=bundle.validation_gateway_completion,
            _factory_token=object(),
        )

    expired_registry = _worker_registry(not_after=NOW + timedelta(minutes=2))
    expired_bundle = _execution_bundle(
        source,
        validation,
        registry=expired_registry,
    )
    with pytest.raises(ValueError, match=r"outside key validity|not currently valid"):
        reporting.promote_governed_web_findings(
            reconciliation=result,
            execution_evidence=expired_bundle.evidence,
            verifier=_verifier(expired_bundle),
            source_run_path=Path("/synthetic/source"),
            validation_run_path=Path("/synthetic/validation"),
            promoted_at=NOW + timedelta(minutes=4),
        )


def test_verifier_binding_is_immutable_and_gateway_lineage_tamper_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, validation, result, verified = _campaign_result()
    _load_runs(monkeypatch, verified)
    bundle = _execution_bundle(source, validation)
    verifier = _verifier(bundle)
    with pytest.raises(AttributeError, match="immutable"):
        verifier._registry = _worker_registry(salt=31)
    with pytest.raises(AttributeError, match="immutable"):
        verifier._source_completion = bundle.validation_completion.completion

    raw = bundle.evidence.model_dump(mode="json", by_alias=True)
    raw["evidenceDigest"] = ""
    raw["sourceGatewayOutcomeDigest"] = _digest("forged-gateway-outcome")
    tampered = reporting.GovernedWebExecutionEvidence.model_validate(raw)
    with pytest.raises(ValueError, match="Gateway receipt or sealed audit lineage"):
        reporting.promote_governed_web_findings(
            reconciliation=result,
            execution_evidence=tampered,
            verifier=verifier,
            source_run_path=Path("/synthetic/source"),
            validation_run_path=Path("/synthetic/validation"),
            promoted_at=NOW + timedelta(minutes=4),
        )


@pytest.mark.parametrize(
    ("target_key", "source_key", "message"),
    [
        (
            "validationObserverProcessId",
            "sourceExecutorProcessId",
            "four distinct process",
        ),
        ("validationObserverKeyId", "sourceExecutorKeyId", "four distinct process"),
        (
            "validationObserverExecutionId",
            "sourceExecutorExecutionId",
            "four distinct process",
        ),
        ("validationActionPermitId", "sourceActionPermitId", "ActionPermits"),
        (
            "validationActionPermitDigest",
            "sourceActionPermitDigest",
            "ActionPermit digests",
        ),
        ("validationGatewayRequestId", "sourceGatewayRequestId", "Gateway requests"),
        (
            "validationGatewayRequestDigest",
            "sourceGatewayRequestDigest",
            "Gateway request digests",
        ),
        ("validationRunId", "sourceRunId", "Run IDs"),
        ("validationRootDigest", "sourceRootDigest", "Run roots"),
        (
            "validationExecutionAttestationDigest",
            "sourceExecutionAttestationDigest",
            "execution attestations",
        ),
        (
            "validationCapabilityGrantId",
            "sourceCapabilityGrantId",
            "Capability Grants",
        ),
        ("validationApprovalId", "sourceApprovalId", "Approvals"),
        (
            "validationApprovalReceiptId",
            "sourceApprovalReceiptId",
            "Approval receipts",
        ),
        (
            "validationWorkerActionEvidenceDigest",
            "sourceWorkerActionEvidenceDigest",
            "Worker action evidence",
        ),
    ],
)
def test_execution_evidence_rejects_shared_authority_or_identity(
    target_key: str,
    source_key: str,
    message: str,
) -> None:
    source, validation, _, _ = _campaign_result()
    raw = _execution_bundle(source, validation).evidence.model_dump(
        mode="json", by_alias=True
    )
    raw["evidenceDigest"] = ""
    raw[target_key] = raw[source_key]

    with pytest.raises(ValidationError, match=message):
        reporting.GovernedWebExecutionEvidence.model_validate(raw)


def _registered_capability() -> RegisteredActionCapability:
    return RegisteredActionCapability(
        capabilityId=CAPABILITY_ID,
        capabilityVersion=CAPABILITY_VERSION,
        definitionDigest=CAPABILITY_DEFINITION_DIGEST,
        toolId="web.authenticated-assessment",
        toolVersion="1.0.0",
        toolDigest=_digest("web-tool"),
        riskTier=ToolRiskTier.T2,
    )


def _action_inputs(
    *,
    role: Literal["source", "validation"],
    run: LocalWebAssessmentRunReference,
    capability: RegisteredActionCapability,
    snapshot: GraphSnapshotRef,
) -> tuple[MissionEnvelope, GraphDecision, ActionProposal, ActionApprovalEnvelope]:
    envelope = MissionEnvelope(
        campaignId=CAMPAIGN_ID,
        runId=run.run_id,
        profileId="web-governed-reporting-test",
        profileVersion="1.0.0",
        profileDigest=_digest("profile"),
        compilerId="pajin.web.governed-compiler",
        compilerVersion="1.0.0",
        compilerDigest=_digest("compiler"),
        sourceCampaignDigest=CAMPAIGN_DIGEST,
        allowedCapabilities=(capability.reference(),),
        allowedTargetDigests=(_target_identity_digest(),),
        maxRiskTier=ToolRiskTier.T2,
        budget=ActionBudgetLimit(
            toolCallLimit=1,
            requestUnitLimit=100,
            costLimitMicrousd=10_000,
        ),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=NOW,
        notBefore=NOW,
        expiresAt=NOW + timedelta(hours=1),
    )
    decision = GraphDecision(
        campaignId=CAMPAIGN_ID,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=_digest(f"{role}-decision-payload"),
        snapshot=snapshot,
        actorId="pajin.web.governed-planner",
        actorDigest=_digest("planner"),
        createdAt=NOW + timedelta(seconds=5),
    )
    request_id = f"gateway_web_{role}_1"
    proposal = ActionProposal(
        campaignId=CAMPAIGN_ID,
        runId=run.run_id,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=decision.snapshot,
        proposerId="pajin.web.governed-planner",
        proposerDigest=_digest("planner"),
        capability=capability.reference(),
        targetDigest=_target_identity_digest(),
        requestId=request_id,
        requestDigest=_digest(f"{role}-gateway-request"),
        normalizedParametersDigest=_digest(f"{role}-parameters"),
        riskTier=ToolRiskTier.T2,
        reservation=ActionBudgetReservation(requestUnits=10, costMicrousd=1_000),
        createdAt=NOW + timedelta(seconds=6),
    )
    release_digest = _digest("capability-release")
    approval = ActionApprovalEnvelope(
        issuer=ActionApprovalIssuerAuthorityBinding(
            authorityId="deployment:web-test-approval",
            authorityVersion="1.0.0",
            implementationType="tests.StaticWebApprovalAuthority",
            contextDigest=_digest("approval-context"),
        ),
        requestedBy="principal:web-planner",
        approvedBy="principal:web-operator",
        campaignId=CAMPAIGN_ID,
        campaignDigest=CAMPAIGN_DIGEST,
        runId=run.run_id,
        missionEnvelope=envelope,
        sourceIntentDigest=decision.decision_payload_digest,
        activationSetDigest=_digest("activation-set"),
        release=ActionApprovalReleaseRef(
            releaseId=f"capability-release_{release_digest}",
            releaseDigest=release_digest,
            capabilityId=CAPABILITY_ID,
            capabilityVersion=CAPABILITY_VERSION,
            capabilityDigest=CAPABILITY_DEFINITION_DIGEST,
        ),
        graphDecision=decision,
        proposal=proposal,
        expectedActionPermitId=action_permit_attempt_id(envelope, proposal, decision),
        sideEffectClass="read-only",
        reservation=proposal.reservation,
        approvedAt=NOW + timedelta(seconds=7),
        notBefore=NOW + timedelta(seconds=8),
        expiresAt=NOW + timedelta(minutes=10),
    )
    return envelope, decision, proposal, approval


def _durable_authorizations(
    tmp_path: Path,
    *,
    source: LocalWebAssessmentRunReference,
    validation: LocalWebAssessmentRunReference,
) -> tuple[SQLiteGraphStore, ActionApprovalAuthorization, ActionApprovalAuthorization]:
    store = SQLiteGraphStore(
        tmp_path / "graph" / "governed-web.sqlite3",
        campaign_id=CAMPAIGN_ID,
    )
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()
    snapshot = GraphSnapshotAuthority(
        creator_id="pajin.web.snapshot-authority",
        creator_digest=_digest("snapshot-authority"),
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=4),
    ).capture(GraphSnapshotReason.CHECKPOINT)
    capability = _registered_capability()
    authority = GraphApprovedActionPermitAuthority(
        campaign_id=CAMPAIGN_ID,
        compiler_id="pajin.web.governed-compiler",
        compiler_version="1.0.0",
        compiler_digest=_digest("compiler"),
        capabilities=ActionCapabilityRegistry([capability]),
        policies=ActionApprovalCapabilityPolicyRegistry(
            (
                ActionApprovalCapabilityPolicy(
                    capability=capability.reference(),
                    sideEffectClass="read-only",
                    approvalRequired=False,
                    cleanupRequired=False,
                ),
            )
        ),
        permit_store=store.permit_store,
        input_authority=_ApprovalInputAuthority(),
        clock=lambda: NOW + timedelta(seconds=9),
        permit_ttl=timedelta(minutes=1),
    )
    source_items = _action_inputs(
        role="source",
        run=source,
        capability=capability,
        snapshot=graph_snapshot_ref(snapshot),
    )
    validation_items = _action_inputs(
        role="validation",
        run=validation,
        capability=capability,
        snapshot=graph_snapshot_ref(snapshot),
    )
    source_authorization = authority.authorize_for_dispatch(
        source_items[0], source_items[2], source_items[1], source_items[3]
    )
    validation_authorization = authority.authorize_for_dispatch(
        validation_items[0], validation_items[2], validation_items[1], validation_items[3]
    )
    return store, source_authorization, validation_authorization


@dataclass(frozen=True, slots=True)
class _ValidatedFlow:
    promotion: reporting.GovernedWebPromotionAuthority
    graph_store: SQLiteGraphStore
    graph_authority: reporting.GovernedWebGraphAuthority
    graph_admission: reporting.GovernedWebGraphAdmissionAuthority
    validation_store: RunStore
    validation_authority: reporting.GovernedWebValidationAuthority


def _validated_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> _ValidatedFlow:
    source, validation, _, _ = _campaign_result()
    graph_store, source_authorization, validation_authorization = _durable_authorizations(
        tmp_path / "graph",
        source=source,
        validation=validation,
    )
    promotion = _promotion(
        monkeypatch,
        source_authorization=source_authorization,
        validation_authorization=validation_authorization,
    )
    graph_authority = reporting.create_governed_web_graph_authority(
        promotion=promotion,
        graph_store=graph_store,
        grant_consumption_store=promotion.grant_consumption_store,
    )
    monkeypatch.setattr(
        reporting,
        "_system_utc_now",
        lambda: NOW + timedelta(minutes=5),
    )
    graph_admission = reporting.admit_governed_web_graph(
        promotion=promotion,
        graph_authority=graph_authority,
    )
    validation_store = RunStore.create(
        tmp_path / "runs",
        "governed-web-reporting-test",
    )
    validation_authority = reporting.write_governed_web_validation_projection(
        validation_store,
        promotion,
        graph_admission,
        decided_at=NOW + timedelta(minutes=5),
    )
    return _ValidatedFlow(
        promotion=promotion,
        graph_store=graph_store,
        graph_authority=graph_authority,
        graph_admission=graph_admission,
        validation_store=validation_store,
        validation_authority=validation_authority,
    )


def test_governed_graph_admits_full_permit_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, validation, _, _ = _campaign_result()
    graph_store, source_authorization, validation_authorization = _durable_authorizations(
        tmp_path,
        source=source,
        validation=validation,
    )
    promotion = _promotion(
        monkeypatch,
        source_authorization=source_authorization,
        validation_authorization=validation_authorization,
    )
    authority = reporting.create_governed_web_graph_authority(
        promotion=promotion,
        graph_store=graph_store,
        grant_consumption_store=promotion.grant_consumption_store,
    )
    monkeypatch.setattr(
        reporting,
        "_system_utc_now",
        lambda: NOW + timedelta(minutes=5),
    )
    admitted = reporting.admit_governed_web_graph(
        promotion=promotion,
        graph_authority=authority,
    )

    assert len(admitted.events) == 9
    assert graph_store.event_log.events() == admitted.events
    assert all(event.decision is GraphAdmissionDecision.ADMITTED for event in admitted.events)
    assert all(
        proposal.lineage.action_permit_id is not None
        and proposal.lineage.capability_grant_id is not None
        for proposal in admitted.proposals
    )
    assert len(admitted.hypothesis_node_ids) == 3
    assert set(admitted.finding_fact_node_ids) == {
        finding.finding_id for finding in promotion.findings
    }
    observation_events = admitted.events[4:6]
    for observation_event in observation_events:
        assert {node.kind for node in observation_event.admitted_nodes} == {
            GraphNodeKind.ACTION,
            GraphNodeKind.OBSERVATION,
            GraphNodeKind.EVIDENCE,
        }
        assert (
            sum(
                edge.relation is GraphRelation.SUPPORTS for edge in observation_event.admitted_edges
            )
            == 3
        )
    assert [event.action_permit_id for event in observation_events] == [
        promotion.execution_evidence.source_action_permit_id,
        promotion.execution_evidence.validation_action_permit_id,
    ]


def _graph_row_counts(path: Path) -> tuple[int, int]:
    with sqlite3.connect(path) as connection:
        event_count = connection.execute("SELECT COUNT(*) FROM graph_events").fetchone()[0]
        node_count = connection.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
    assert isinstance(event_count, int)
    assert isinstance(node_count, int)
    return event_count, node_count


def test_graph_batch_middle_equivocation_is_all_or_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed = _validated_flow(tmp_path / "seed", monkeypatch)
    source, validation, _, _ = _campaign_result()
    graph_store, source_authorization, validation_authorization = _durable_authorizations(
        tmp_path / "target",
        source=source,
        validation=validation,
    )
    promotion = _promotion(
        monkeypatch,
        source_authorization=source_authorization,
        validation_authorization=validation_authorization,
    )
    verifier = reporting.GovernedWebPermitLineageVerifier(
        permit_store=graph_store.permit_store,
        grant_consumption_store=promotion.grant_consumption_store,
        execution_evidence=promotion.execution_evidence,
    )
    event_log = SQLiteGraphEventLog(graph_store.path, campaign_id=CAMPAIGN_ID)
    generic = GraphAdmissionAuthority(
        campaign_id=CAMPAIGN_ID,
        authority_id=reporting.GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
        authority_digest=reporting.GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
        producers=GraphProducerRegistry([reporting.governed_web_graph_producer_registration()]),
        lineage_verifier=verifier,
        event_log=event_log,
        clock=lambda: NOW + timedelta(minutes=5),
    )
    raw_middle = seed.graph_admission.proposals[2].model_dump(mode="json", by_alias=True)
    raw_middle["edges"][0]["authorityDigest"] = "f" * 64
    raw_middle["edges"][0]["edgeId"] = ""
    rejected = generic.submit(parse_graph_proposal(raw_middle)).event
    assert rejected.decision is GraphAdmissionDecision.REJECTED
    baseline_events = SQLiteGraphEventLog.events(event_log)
    baseline_counts = _graph_row_counts(graph_store.path)

    authority = reporting.create_governed_web_graph_authority(
        promotion=promotion,
        graph_store=graph_store,
        grant_consumption_store=promotion.grant_consumption_store,
    )
    monkeypatch.setattr(
        reporting,
        "_system_utc_now",
        lambda: NOW + timedelta(minutes=5),
    )
    with pytest.raises(ValueError, match="equivocated"):
        reporting.admit_governed_web_graph(
            promotion=promotion,
            graph_authority=authority,
        )

    assert SQLiteGraphEventLog.events(event_log) == baseline_events
    assert _graph_row_counts(graph_store.path) == baseline_counts


@pytest.mark.parametrize("fault", ["node-write", "head-change"])
def test_graph_batch_store_fault_or_head_change_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: Literal["node-write", "head-change"],
) -> None:
    seed = _validated_flow(tmp_path / "seed", monkeypatch)
    source, validation, _, _ = _campaign_result()
    graph_store, source_authorization, validation_authorization = _durable_authorizations(
        tmp_path / "target",
        source=source,
        validation=validation,
    )
    promotion = _promotion(
        monkeypatch,
        source_authorization=source_authorization,
        validation_authorization=validation_authorization,
    )
    authority = reporting.create_governed_web_graph_authority(
        promotion=promotion,
        graph_store=graph_store,
        grant_consumption_store=promotion.grant_consumption_store,
    )
    monkeypatch.setattr(
        reporting,
        "_system_utc_now",
        lambda: NOW + timedelta(minutes=5),
    )
    if fault == "node-write":
        monkeypatch.setattr(
            reporting,
            "_node_bytes",
            lambda _node: (_ for _ in ()).throw(OSError("injected Graph node write fault")),
        )
        expected = "injected Graph node write fault"
    else:
        original = _events_from_connection
        calls = 0

        def changed_head(
            connection: sqlite3.Connection,
            *,
            campaign_id: str,
        ) -> tuple[GraphAdmissionEvent, ...]:
            nonlocal calls
            calls += 1
            events = original(connection, campaign_id=campaign_id)
            if calls == 2:
                return (*events, seed.graph_admission.events[0])
            return events

        monkeypatch.setattr(reporting, "_events_from_connection", changed_head)
        expected = "head changed"

    with pytest.raises((OSError, ValueError), match=expected):
        reporting.admit_governed_web_graph(
            promotion=promotion,
            graph_authority=authority,
        )

    assert _graph_row_counts(graph_store.path) == (0, 0)


def test_graph_requires_durable_receipts_and_rejects_method_shadowing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    promotion_without_receipts = _promotion(monkeypatch)
    empty_store = SQLiteGraphStore(
        tmp_path / "empty" / "governed-web.sqlite3",
        campaign_id=CAMPAIGN_ID,
    )
    with pytest.raises(GraphLineageVerificationError, match="authorization is absent"):
        reporting.create_governed_web_graph_authority(
            promotion=promotion_without_receipts,
            graph_store=empty_store,
            grant_consumption_store=promotion_without_receipts.grant_consumption_store,
        )
    assert empty_store.event_log.events() == ()

    source, validation, _, _ = _campaign_result()
    graph_store, source_authorization, validation_authorization = _durable_authorizations(
        tmp_path / "valid",
        source=source,
        validation=validation,
    )
    promotion = _promotion(
        monkeypatch,
        source_authorization=source_authorization,
        validation_authorization=validation_authorization,
    )
    authority = reporting.create_governed_web_graph_authority(
        promotion=promotion,
        graph_store=graph_store,
        grant_consumption_store=promotion.grant_consumption_store,
    )
    authority.graph_store.event_log.events = lambda: ()  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="instance method override"):
        reporting.admit_governed_web_graph(
            promotion=promotion,
            graph_authority=authority,
        )
    assert type(graph_store.event_log).events(graph_store.event_log) == ()

    factory_parameters = inspect.signature(
        reporting.create_governed_web_graph_authority
    ).parameters
    assert tuple(factory_parameters) == (
        "promotion",
        "graph_store",
        "grant_consumption_store",
        "graph_database_authority",
    )


def test_graph_admission_reloads_exact_database_and_authorities_are_immutable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, validation, _, _ = _campaign_result()
    graph_store, source_authorization, validation_authorization = _durable_authorizations(
        tmp_path / "graph",
        source=source,
        validation=validation,
    )
    promotion = _promotion(
        monkeypatch,
        source_authorization=source_authorization,
        validation_authorization=validation_authorization,
    )
    graph_authority = reporting.create_governed_web_graph_authority(
        promotion=promotion,
        graph_store=graph_store,
        grant_consumption_store=promotion.grant_consumption_store,
    )
    monkeypatch.setattr(
        reporting,
        "_system_utc_now",
        lambda: NOW + timedelta(minutes=5),
    )
    admission = reporting.admit_governed_web_graph(
        promotion=promotion,
        graph_authority=graph_authority,
    )
    with pytest.raises(AttributeError, match="immutable"):
        graph_authority._promotion_digest = "f" * 64
    with pytest.raises(AttributeError, match="immutable"):
        admission._events = ()

    cached = admission.events
    original_path = graph_store.path.with_suffix(".original.sqlite3")
    graph_store.path.rename(original_path)
    replacement = SQLiteGraphStore(graph_store.path, campaign_id=CAMPAIGN_ID)
    graph_store.event_log.events = lambda: cached  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="binding differs from its factory"):
        admission._require_durable_reload()
    assert replacement.event_log.events() == ()

    validation_store = RunStore.create(tmp_path / "runs", "replaced-graph")
    with pytest.raises(ValueError, match="binding differs from its factory"):
        reporting.write_governed_web_validation_projection(
            validation_store,
            promotion,
            admission,
            decided_at=NOW + timedelta(minutes=5),
        )
    assert not (validation_store.path / "governed-web-promotion.json").exists()
    assert not validation_store.integrity_path.exists()


def test_graph_path_swap_to_stripped_database_rejects_all_downstream_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _validated_flow(tmp_path / "flow", monkeypatch)
    stripped = SQLiteGraphStore(
        tmp_path / "stripped" / "governed-web.sqlite3",
        campaign_id=CAMPAIGN_ID,
    )
    stripped.event_log.claim_writer(
        reporting.GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_ID,
        reporting.GOVERNED_WEB_GRAPH_ADMISSION_AUTHORITY_DIGEST,
    )
    with sqlite3.connect(stripped.path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("ATTACH DATABASE ? AS source", (os.fspath(flow.graph_store.path),))
        connection.execute("INSERT INTO graph_events SELECT * FROM source.graph_events")
        connection.execute("INSERT INTO graph_nodes SELECT * FROM source.graph_nodes")
        connection.commit()
    with sqlite3.connect(stripped.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM graph_events").fetchone() == (9,)
        assert connection.execute("SELECT COUNT(*) FROM graph_nodes").fetchone() == (13,)
        assert connection.execute("SELECT COUNT(*) FROM graph_action_permits").fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM graph_action_approval_envelopes"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM graph_action_approval_consumptions"
        ).fetchone() == (0,)

    flow.graph_store.path = stripped.path
    flow.graph_store.event_log.path = stripped.path
    flow.graph_store.permit_store.path = stripped.path
    with pytest.raises(ValueError, match="binding differs from its factory"):
        flow.graph_admission._require_durable_reload()

    rejected_validation = RunStore.create(
        tmp_path / "rejected-runs",
        "stripped-graph",
    )
    with pytest.raises(ValueError, match="binding differs from its factory"):
        reporting.write_governed_web_validation_projection(
            rejected_validation,
            flow.promotion,
            flow.graph_admission,
            decided_at=NOW + timedelta(minutes=6),
        )
    assert [path for path in rejected_validation.path.rglob("*") if path.is_file()] == []

    export_output = tmp_path / "stripped-export"
    with pytest.raises(ValueError, match="binding differs from its factory"):
        reporting.write_verified_governed_web_exports(
            validation=flow.validation_authority,
            output_directory=export_output,
            prepared_at=NOW + timedelta(minutes=6),
        )
    assert not export_output.exists()

    poc_output = tmp_path / "stripped-poc"
    with pytest.raises(ValueError, match="binding differs from its factory"):
        reporting.write_redacted_governed_web_poc(
            validation=flow.validation_authority,
            output_directory=poc_output,
            origin=ORIGIN,
            adapter_ref="juice-shop-local/v1",
        )
    assert not poc_output.exists()


def test_serialized_promotion_cannot_recreate_downstream_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _promotion(monkeypatch)
    raw = authority.promotion.model_dump(mode="json", by_alias=True)
    raw["promotionDigest"] = ""
    raw["findings"][0]["summary"] = "caller-injected validated claim"
    forged = reporting.GovernedWebPromotion.model_validate(raw)
    assert forged.findings != authority.findings

    graph_store = SQLiteGraphStore(
        tmp_path / "forged" / "governed-web.sqlite3",
        campaign_id=CAMPAIGN_ID,
    )
    with pytest.raises(TypeError, match="Promotion authority"):
        reporting.create_governed_web_graph_authority(
            promotion=forged,  # type: ignore[arg-type]
            graph_store=graph_store,
            grant_consumption_store=authority.grant_consumption_store,
        )
    run_store = RunStore.create(tmp_path / "forged-runs", "forged-promotion")
    with pytest.raises(TypeError, match="Promotion authority"):
        reporting.write_governed_web_validation_projection(
            run_store,
            forged,  # type: ignore[arg-type]
            None,  # type: ignore[arg-type]
            decided_at=NOW + timedelta(minutes=5),
        )
    assert not (run_store.path / "governed-web-promotion.json").exists()
    assert not run_store.integrity_path.exists()


def test_promotion_authority_rejects_replace_copy_pickle_and_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _validated_flow(tmp_path / "flow", monkeypatch)
    authority = flow.promotion
    graph_before = _graph_row_counts(flow.graph_store.path)
    validation_before = verify_run_integrity(flow.validation_store.path)
    decoy = tmp_path / "decoy-source-run"

    with pytest.raises(TypeError, match="dataclass"):
        replace(authority, _source_run_path=decoy)  # type: ignore[type-var]
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(authority)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(authority)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(authority)
    with pytest.raises(AttributeError, match="immutable"):
        authority._source_run_path = decoy
    with pytest.raises(AttributeError, match="immutable"):
        authority._validated_gateway_run_paths = lambda: (decoy, decoy)  # type: ignore[method-assign]

    assert not decoy.exists()
    assert _graph_row_counts(flow.graph_store.path) == graph_before
    assert verify_run_integrity(flow.validation_store.path) == validation_before
    assert not (tmp_path / "replaced-export").exists()
    assert not (tmp_path / "replaced-poc").exists()


def test_validation_sarif_poc_and_delivery_readiness_stay_local(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, validation, _, _ = _campaign_result()
    graph_store, source_authorization, validation_authorization = _durable_authorizations(
        tmp_path / "graph",
        source=source,
        validation=validation,
    )
    promotion = _promotion(
        monkeypatch,
        source_authorization=source_authorization,
        validation_authorization=validation_authorization,
    )
    graph_authority = reporting.create_governed_web_graph_authority(
        promotion=promotion,
        graph_store=graph_store,
        grant_consumption_store=promotion.grant_consumption_store,
    )
    monkeypatch.setattr(
        reporting,
        "_system_utc_now",
        lambda: NOW + timedelta(minutes=5),
    )
    graph_admission = reporting.admit_governed_web_graph(
        promotion=promotion,
        graph_authority=graph_authority,
    )
    store = RunStore.create(tmp_path / "runs", "governed-web-reporting-test")
    authority = reporting.write_governed_web_validation_projection(
        store,
        promotion,
        graph_admission,
        decided_at=NOW + timedelta(minutes=5),
    )
    poc_root = tmp_path / "poc-bundles" / store.run_id
    poc = reporting.write_redacted_governed_web_poc(
        validation=authority,
        output_directory=poc_root,
        origin="http://127.0.0.1:3000",
        adapter_ref="juice-shop-local/v1",
    )
    exports = reporting.write_verified_governed_web_exports(
        validation=authority,
        output_directory=tmp_path / "exports" / store.run_id,
        prepared_at=NOW + timedelta(minutes=6),
    )

    assert authority.finding_count == 3
    assert exports.sarif.finding_count == 3
    assert exports.sarif_path.parent != store.path
    assert exports.delivery_manifest.external_delivery_performed is False
    assert exports.delivery_manifest.delivery_authorization_present is False
    assert exports.delivery_manifest.delivery_receipt_authority is False
    assert exports.delivery_manifest.blocked_reason
    assert verify_run_integrity(store.path).root_digest == authority.final_root_digest

    decisions = json.loads(
        (store.path / VERSIONED_VALIDATION_DECISIONS_PATH).read_text(encoding="utf-8")
    )["decisions"]
    assert all(decision["decision_id"].startswith("decision_replay_") for decision in decisions)
    assert all(
        {
            "candidate-bound-validator-assessment",
            "independent-reproduction",
            "replay-lineage",
            "replay-oracle",
            "replay-receipt-integrity",
        }
        == {check["check_id"] for check in decision["checks"]}
        for decision in decisions
    )

    report = (store.path / VERSIONED_VALIDATION_REPORT_PATH).read_text(encoding="utf-8")
    for finding in promotion.findings:
        expected_finding_section = "\n".join(
            [
                f"### {finding.title}",
                "",
                f"- Finding ID: `{finding.finding_id}`",
                f"- Severity: `{finding.severity.value}`",
                f"- Threat class: `{finding.threat_class}`",
                f"- Target: `{finding.target}`",
                f"- Affected component: `{finding.affected_component}`",
                f"- Confidence: `{finding.confidence:.2f}`",
                "- Validated: `true`",
                f"- Summary: {finding.summary}",
                f"- Impact assessment: {finding.impact}",
                f"- Root cause: {finding.root_cause}",
                "",
                "#### Reproduction",
                "",
                *(f"{index}. {step}" for index, step in enumerate(finding.reproduction, 1)),
                "",
                "#### Evidence",
                "",
                *(f"- `{reference}`" for reference in finding.evidence),
                "",
                "#### Remediation",
                "",
                *(f"- {item}" for item in finding.remediation),
            ]
        )
        assert expected_finding_section in report
    assert "External delivery performed: `false`" in report

    script = (poc_root / poc.script_path).read_text(encoding="utf-8")
    assert "web-campaign-run-governed-local" in script
    assert "DEFAULT_ADAPTER_REF='juice-shop-local/v1'" in script
    assert '--adapter-ref "$ADAPTER_REF"' in script
    assert "--authorized-local-lab" in script
    assert "password" not in script.lower()
    assert "token" not in script.lower()
    assert _digest("not-a-real-secret") not in script
    assert sha256(script.encode()).hexdigest() == poc.script_sha256
    readme = (poc_root / poc.readme_path).read_text(encoding="utf-8")
    assert sha256(readme.encode()).hexdigest() == poc.readme_sha256
    if os.name == "posix":
        assert stat.S_IMODE((poc_root / poc.script_path).stat().st_mode) == 0o700

    sarif = json.loads(exports.sarif_path.read_text(encoding="utf-8"))
    assert len(sarif["runs"][0]["results"]) == 3
    delivery = json.loads(exports.delivery_manifest_path.read_text(encoding="utf-8"))
    assert delivery["externalDeliveryPerformed"] is False
    assert delivery["distinctCoordinatorRecordSupplied"] is False
    assert "delivery_record" not in inspect.signature(
        reporting.write_verified_governed_web_exports
    ).parameters

    delivery["externalDeliveryPerformed"] = True
    exports.delivery_manifest_path.write_text(
        json.dumps(delivery, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        reporting.load_verified_governed_web_delivery_manifest(
            exports.delivery_manifest_path,
            expected_source_run_id=exports.sarif.source_run_id,
            expected_source_root_digest=exports.sarif.source_root_digest,
            expected_finding_set_digest=exports.sarif.finding_set_digest,
            expected_sarif_digest=exports.sarif.sarif_digest,
            expected_finding_count=exports.sarif.finding_count,
        )


def test_validation_authority_rejects_reconstruction_generic_run_and_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _validated_flow(tmp_path / "flow", monkeypatch)
    authority = flow.validation_authority

    with pytest.raises(AttributeError, match="immutable"):
        authority._export_consumed = False
    with pytest.raises(AttributeError, match="immutable"):
        authority._run_path = tmp_path / "substituted"
    with pytest.raises(TypeError, match="code-owned writer"):
        reporting.GovernedWebValidationAuthority(
            _factory_token=object(),
            run_path=flow.validation_store.path,
            run_id=flow.validation_store.run_id,
            candidate_source_root_digest=authority.candidate_source_root_digest,
            final_root_digest=authority.final_root_digest,
            promotion_authority=flow.promotion,
            graph_admission_authority=flow.graph_admission,
        )

    generic_store = RunStore.create(tmp_path / "generic-runs", "generic-replay")
    generic_store.append_event("generic.completed", {"status": "completed"})
    generic_store.seal()
    generic_output = tmp_path / "generic-export"
    with pytest.raises(TypeError, match="opaque validation authority"):
        reporting.write_verified_governed_web_exports(
            validation=generic_store,  # type: ignore[arg-type]
            output_directory=generic_output,
            prepared_at=NOW + timedelta(minutes=6),
        )
    assert not generic_output.exists()

    first_output = tmp_path / "first-export"
    bundle = reporting.write_verified_governed_web_exports(
        validation=authority,
        output_directory=first_output,
        prepared_at=NOW + timedelta(minutes=6),
    )
    assert {path.name for path in first_output.iterdir()} == {
        "delivery-readiness.json",
        "findings.sarif",
    }
    assert bundle.sarif.finding_count == authority.finding_count

    second_output = tmp_path / "second-export"
    with pytest.raises(ValueError, match="already consumed"):
        reporting.write_verified_governed_web_exports(
            validation=authority,
            output_directory=second_output,
            prepared_at=NOW + timedelta(minutes=7),
        )
    assert not second_output.exists()


def test_validation_authority_rejects_copy_pickle_and_concurrent_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _validated_flow(tmp_path / "flow", monkeypatch)
    authority = flow.validation_authority
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(authority)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(authority)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(authority)
    assert not (tmp_path / "copy-export").exists()
    assert not (tmp_path / "copy-poc").exists()

    export_destinations = tuple(tmp_path / f"concurrent-export-{index}" for index in range(2))

    def publish_export(destination: Path) -> bool:
        try:
            reporting.write_verified_governed_web_exports(
                validation=authority,
                output_directory=destination,
                prepared_at=NOW + timedelta(minutes=6),
            )
        except ValueError as exc:
            assert "already consumed" in str(exc)
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        export_results = list(pool.map(publish_export, export_destinations))
    assert export_results.count(True) == 1
    assert sum(destination.exists() for destination in export_destinations) == 1

    poc_destinations = tuple(tmp_path / f"concurrent-poc-{index}" for index in range(2))

    def publish_poc(destination: Path) -> bool:
        try:
            reporting.write_redacted_governed_web_poc(
                validation=authority,
                output_directory=destination,
                origin=ORIGIN,
                adapter_ref="juice-shop-local/v1",
            )
        except ValueError as exc:
            assert "already consumed" in str(exc)
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        poc_results = list(pool.map(publish_poc, poc_destinations))
    assert poc_results.count(True) == 1
    assert sum(destination.exists() for destination in poc_destinations) == 1


def test_governed_outputs_reject_protected_run_and_symlink_aliases_before_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _validated_flow(tmp_path / "flow", monkeypatch)
    authority = flow.validation_authority
    before = verify_run_integrity(flow.validation_store.path)

    direct_poc = flow.validation_store.path / "nested-poc"
    with pytest.raises(ValueError, match="overlaps a protected authority store"):
        reporting.write_redacted_governed_web_poc(
            validation=authority,
            output_directory=direct_poc,
            origin=ORIGIN,
            adapter_ref="juice-shop-local/v1",
        )
    assert not direct_poc.exists()

    with pytest.raises(ValueError, match="overlaps a protected authority store"):
        reporting.write_verified_governed_web_exports(
            validation=authority,
            output_directory=flow.validation_store.path,
            prepared_at=NOW + timedelta(minutes=6),
        )

    mixed_case_run = Path(os.fspath(flow.validation_store.path).upper())
    if mixed_case_run.exists() and os.path.samefile(
        mixed_case_run,
        flow.validation_store.path,
    ):
        mixed_poc = mixed_case_run / "mixed-case-poc"
        with pytest.raises(ValueError, match="overlaps a protected authority store"):
            reporting.write_redacted_governed_web_poc(
                validation=authority,
                output_directory=mixed_poc,
                origin=ORIGIN,
                adapter_ref="juice-shop-local/v1",
            )
        assert not (flow.validation_store.path / "mixed-case-poc").exists()
        mixed_export = mixed_case_run / "mixed-case-export"
        with pytest.raises(ValueError, match="overlaps a protected authority store"):
            reporting.write_verified_governed_web_exports(
                validation=authority,
                output_directory=mixed_export,
                prepared_at=NOW + timedelta(minutes=6),
            )
        assert not (flow.validation_store.path / "mixed-case-export").exists()

    run_alias = tmp_path / "validation-run-alias"
    run_alias.symlink_to(flow.validation_store.path, target_is_directory=True)
    aliased_poc = run_alias / "aliased-poc"
    with pytest.raises(ValueError, match="overlaps a protected authority store"):
        reporting.write_redacted_governed_web_poc(
            validation=authority,
            output_directory=aliased_poc,
            origin=ORIGIN,
            adapter_ref="juice-shop-local/v1",
        )
    assert not (flow.validation_store.path / "aliased-poc").exists()

    aliased_export = run_alias / "aliased-export"
    with pytest.raises(ValueError, match="overlaps a protected authority store"):
        reporting.write_verified_governed_web_exports(
            validation=authority,
            output_directory=aliased_export,
            prepared_at=NOW + timedelta(minutes=6),
        )
    assert not (flow.validation_store.path / "aliased-export").exists()
    assert verify_run_integrity(flow.validation_store.path) == before

    gateway_paths = (
        flow.promotion._source_gateway_run_path,
        flow.promotion._validation_gateway_run_path,
    )
    gateway_before = tuple(verify_run_integrity(path) for path in gateway_paths)
    for index, gateway_path in enumerate(gateway_paths):
        nested_poc = gateway_path / f"nested-poc-{index}"
        with pytest.raises(ValueError, match="overlaps a protected authority store"):
            reporting.write_redacted_governed_web_poc(
                validation=authority,
                output_directory=nested_poc,
                origin=ORIGIN,
                adapter_ref="juice-shop-local/v1",
            )
        assert not nested_poc.exists()

        nested_export = gateway_path / f"nested-export-{index}"
        with pytest.raises(ValueError, match="overlaps a protected authority store"):
            reporting.write_verified_governed_web_exports(
                validation=authority,
                output_directory=nested_export,
                prepared_at=NOW + timedelta(minutes=6),
            )
        assert not nested_export.exists()

        gateway_alias = tmp_path / f"gateway-run-alias-{index}"
        gateway_alias.symlink_to(gateway_path, target_is_directory=True)
        with pytest.raises(ValueError, match="overlaps a protected authority store"):
            reporting.write_redacted_governed_web_poc(
                validation=authority,
                output_directory=gateway_alias / "aliased-poc",
                origin=ORIGIN,
                adapter_ref="juice-shop-local/v1",
            )
        with pytest.raises(ValueError, match="overlaps a protected authority store"):
            reporting.write_verified_governed_web_exports(
                validation=authority,
                output_directory=gateway_alias / "aliased-export",
                prepared_at=NOW + timedelta(minutes=6),
            )

        mixed_case_gateway = Path(os.fspath(gateway_path).upper())
        if mixed_case_gateway.exists() and os.path.samefile(
            mixed_case_gateway,
            gateway_path,
        ):
            with pytest.raises(ValueError, match="overlaps a protected authority store"):
                reporting.write_redacted_governed_web_poc(
                    validation=authority,
                    output_directory=mixed_case_gateway / "mixed-case-poc",
                    origin=ORIGIN,
                    adapter_ref="juice-shop-local/v1",
                )
            with pytest.raises(ValueError, match="overlaps a protected authority store"):
                reporting.write_verified_governed_web_exports(
                    validation=authority,
                    output_directory=mixed_case_gateway / "mixed-case-export",
                    prepared_at=NOW + timedelta(minutes=6),
                )
    assert tuple(verify_run_integrity(path) for path in gateway_paths) == gateway_before

    safe_poc = tmp_path / "safe-poc"
    reporting.write_redacted_governed_web_poc(
        validation=authority,
        output_directory=safe_poc,
        origin=ORIGIN,
        adapter_ref="juice-shop-local/v1",
    )
    safe_export = tmp_path / "safe-export"
    reporting.write_verified_governed_web_exports(
        validation=authority,
        output_directory=safe_export,
        prepared_at=NOW + timedelta(minutes=6),
    )
    assert (safe_poc / "poc/manifest.json").is_file()
    assert (safe_export / "findings.sarif").is_file()
    assert verify_run_integrity(flow.validation_store.path) == before


@pytest.mark.parametrize("bundle_kind", ["poc", "export"])
def test_governed_bundle_publish_rejects_destination_parent_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bundle_kind: str,
) -> None:
    flow = _validated_flow(tmp_path / f"{bundle_kind}-flow", monkeypatch)
    authority = flow.validation_authority
    protected_runs = (
        flow.validation_store.path,
        flow.promotion._source_gateway_run_path,
        flow.promotion._validation_gateway_run_path,
    )
    protected_before = tuple(verify_run_integrity(path) for path in protected_runs)
    switch_parent = tmp_path / f"{bundle_kind}-switch"
    parked_parent = tmp_path / f"{bundle_kind}-parked"
    switch_parent.mkdir()
    unsafe_destination = switch_parent / "bundle"

    def swap_parent(_destination: Path) -> None:
        switch_parent.rename(parked_parent)
        switch_parent.symlink_to(
            flow.promotion._source_gateway_run_path,
            target_is_directory=True,
        )

    with monkeypatch.context() as patch:
        patch.setattr(reporting, "_before_governed_bundle_publish", swap_parent)
        with pytest.raises(ValueError, match=r"parent (?:contains an alias|path changed)"):
            if bundle_kind == "poc":
                reporting.write_redacted_governed_web_poc(
                    validation=authority,
                    output_directory=unsafe_destination,
                    origin=ORIGIN,
                    adapter_ref="juice-shop-local/v1",
                )
            else:
                reporting.write_verified_governed_web_exports(
                    validation=authority,
                    output_directory=unsafe_destination,
                    prepared_at=NOW + timedelta(minutes=6),
                )

    assert not (flow.promotion._source_gateway_run_path / "bundle").exists()
    assert list(parked_parent.iterdir()) == []
    assert tuple(verify_run_integrity(path) for path in protected_runs) == protected_before
    switch_parent.unlink()
    parked_parent.rename(switch_parent)

    safe_destination = tmp_path / f"{bundle_kind}-safe"
    if bundle_kind == "poc":
        reporting.write_redacted_governed_web_poc(
            validation=authority,
            output_directory=safe_destination,
            origin=ORIGIN,
            adapter_ref="juice-shop-local/v1",
        )
        assert (safe_destination / "poc/manifest.json").is_file()
    else:
        reporting.write_verified_governed_web_exports(
            validation=authority,
            output_directory=safe_destination,
            prepared_at=NOW + timedelta(minutes=6),
        )
        assert (safe_destination / "findings.sarif").is_file()
    assert tuple(verify_run_integrity(path) for path in protected_runs) == protected_before


@pytest.mark.parametrize("bundle_kind", ["poc", "export"])
def test_governed_bundle_publish_rejects_staging_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bundle_kind: str,
) -> None:
    flow = _validated_flow(tmp_path / f"{bundle_kind}-flow", monkeypatch)
    authority = flow.validation_authority
    destination = tmp_path / f"{bundle_kind}-destination"
    parked = tmp_path / f"{bundle_kind}-legitimate-staging"
    attacker_staging: Path | None = None

    def replace_staging(publish_destination: Path) -> None:
        nonlocal attacker_staging
        candidates = tuple(
            path
            for path in publish_destination.parent.iterdir()
            if path.name.startswith(f".{publish_destination.name}.staging-")
        )
        assert len(candidates) == 1
        candidates[0].rename(parked)
        candidates[0].mkdir(mode=0o700)
        (candidates[0] / "attacker.txt").write_text("not governed\n", encoding="utf-8")
        attacker_staging = candidates[0]

    with monkeypatch.context() as patch:
        patch.setattr(reporting, "_before_governed_bundle_publish", replace_staging)
        with pytest.raises(ValueError, match="staging name changed"):
            if bundle_kind == "poc":
                reporting.write_redacted_governed_web_poc(
                    validation=authority,
                    output_directory=destination,
                    origin=ORIGIN,
                    adapter_ref="juice-shop-local/v1",
                )
            else:
                reporting.write_verified_governed_web_exports(
                    validation=authority,
                    output_directory=destination,
                    prepared_at=NOW + timedelta(minutes=6),
                )

    assert not destination.exists()
    assert parked.is_dir()
    assert attacker_staging is not None
    assert (attacker_staging / "attacker.txt").read_text(encoding="utf-8") == "not governed\n"

    safe_destination = tmp_path / f"{bundle_kind}-safe"
    if bundle_kind == "poc":
        reporting.write_redacted_governed_web_poc(
            validation=authority,
            output_directory=safe_destination,
            origin=ORIGIN,
            adapter_ref="juice-shop-local/v1",
        )
        assert (safe_destination / "poc/manifest.json").is_file()
    else:
        reporting.write_verified_governed_web_exports(
            validation=authority,
            output_directory=safe_destination,
            prepared_at=NOW + timedelta(minutes=6),
        )
        assert (safe_destination / "findings.sarif").is_file()


@pytest.mark.parametrize("bundle_kind", ["poc", "export"])
def test_governed_bundle_rejects_unrelated_immutable_run_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bundle_kind: str,
) -> None:
    flow = _validated_flow(tmp_path / f"{bundle_kind}-flow", monkeypatch)
    authority = flow.validation_authority
    victim = RunStore.create(tmp_path / "victim-runs", f"victim-{bundle_kind}")
    victim.append_event("victim.completed", {"status": "sealed"})
    victim.seal()
    before = verify_run_integrity(victim.path)
    unsafe = victim.path / f"{bundle_kind}-bundle"

    with pytest.raises(ValueError, match="inside any immutable Run"):
        if bundle_kind == "poc":
            reporting.write_redacted_governed_web_poc(
                validation=authority,
                output_directory=unsafe,
                origin=ORIGIN,
                adapter_ref="juice-shop-local/v1",
            )
        else:
            reporting.write_verified_governed_web_exports(
                validation=authority,
                output_directory=unsafe,
                prepared_at=NOW + timedelta(minutes=6),
            )
    assert not unsafe.exists()
    assert verify_run_integrity(victim.path) == before

    safe = tmp_path / f"{bundle_kind}-safe"
    if bundle_kind == "poc":
        reporting.write_redacted_governed_web_poc(
            validation=authority,
            output_directory=safe,
            origin=ORIGIN,
            adapter_ref="juice-shop-local/v1",
        )
        assert (safe / "poc/manifest.json").is_file()
    else:
        reporting.write_verified_governed_web_exports(
            validation=authority,
            output_directory=safe,
            prepared_at=NOW + timedelta(minutes=6),
        )
        assert (safe / "findings.sarif").is_file()


def test_governed_poc_and_export_roots_protect_each_other_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poc_first = _validated_flow(tmp_path / "poc-first-flow", monkeypatch)
    poc_root = tmp_path / "published-poc"
    poc_manifest = reporting.write_redacted_governed_web_poc(
        validation=poc_first.validation_authority,
        output_directory=poc_root,
        origin=ORIGIN,
        adapter_ref="juice-shop-local/v1",
    )
    for overlapping in (poc_root, poc_root / "nested-export", poc_root.parent):
        with pytest.raises(ValueError, match="overlaps a protected authority store"):
            reporting.write_verified_governed_web_exports(
                validation=poc_first.validation_authority,
                output_directory=overlapping,
                prepared_at=NOW + timedelta(minutes=6),
            )
    assert not (poc_root / "nested-export").exists()
    reporting.load_verified_redacted_governed_web_poc_manifest(
        poc_root / "poc/manifest.json",
        expected=poc_manifest,
        bundle_root=poc_root,
    )
    safe_export = tmp_path / "poc-first-safe-export"
    reporting.write_verified_governed_web_exports(
        validation=poc_first.validation_authority,
        output_directory=safe_export,
        prepared_at=NOW + timedelta(minutes=6),
    )
    assert {path.name for path in safe_export.iterdir()} == {
        "delivery-readiness.json",
        "findings.sarif",
    }

    export_first = _validated_flow(tmp_path / "export-first-flow", monkeypatch)
    export_root = tmp_path / "published-export"
    export_bundle = reporting.write_verified_governed_web_exports(
        validation=export_first.validation_authority,
        output_directory=export_root,
        prepared_at=NOW + timedelta(minutes=6),
    )
    for overlapping in (export_root, export_root / "nested-poc", export_root.parent):
        with pytest.raises(ValueError, match="overlaps a protected authority store"):
            reporting.write_redacted_governed_web_poc(
                validation=export_first.validation_authority,
                output_directory=overlapping,
                origin=ORIGIN,
                adapter_ref="juice-shop-local/v1",
            )
    assert not (export_root / "nested-poc").exists()
    reporting.load_verified_governed_web_delivery_manifest(
        export_bundle.delivery_manifest_path,
        expected_source_run_id=export_bundle.sarif.source_run_id,
        expected_source_root_digest=export_bundle.sarif.source_root_digest,
        expected_finding_set_digest=export_bundle.sarif.finding_set_digest,
        expected_sarif_digest=export_bundle.sarif.sarif_digest,
        expected_finding_count=export_bundle.sarif.finding_count,
    )
    safe_poc = tmp_path / "export-first-safe-poc"
    reporting.write_redacted_governed_web_poc(
        validation=export_first.validation_authority,
        output_directory=safe_poc,
        origin=ORIGIN,
        adapter_ref="juice-shop-local/v1",
    )
    assert (safe_poc / "poc/manifest.json").is_file()


def test_governed_export_is_atomic_and_failed_preflight_does_not_consume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _validated_flow(tmp_path / "flow", monkeypatch)
    authority = flow.validation_authority

    invalid_output = tmp_path / "invalid-time-export"
    with pytest.raises(ValueError, match="explicit UTC offset"):
        reporting.write_verified_governed_web_exports(
            validation=authority,
            output_directory=invalid_output,
            prepared_at=datetime(2026, 9, 14, 3, 6),
        )
    assert not invalid_output.exists()

    stale_output = tmp_path / "stale-export"
    stale_output.mkdir()
    stale_marker = stale_output / "stale.txt"
    stale_marker.write_text("do not reuse\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="destination already exists"):
        reporting.write_verified_governed_web_exports(
            validation=authority,
            output_directory=stale_output,
            prepared_at=NOW + timedelta(minutes=6),
        )
    assert list(stale_output.iterdir()) == [stale_marker]

    original_write = reporting._write_bundle_file_at

    def fail_manifest_write(
        directory_fd: int,
        name: str,
        content: bytes,
        *,
        mode: int,
        label: str,
    ) -> None:
        if label == "governed WEB delivery-readiness manifest":
            raise OSError("simulated paired export write failure")
        original_write(
            directory_fd,
            name,
            content,
            mode=mode,
            label=label,
        )

    fault_parent = tmp_path / "fault-parent"
    fault_output = fault_parent / "export"
    with monkeypatch.context() as patch:
        patch.setattr(reporting, "_write_bundle_file_at", fail_manifest_write)
        with pytest.raises(OSError, match="paired export write failure"):
            reporting.write_verified_governed_web_exports(
                validation=authority,
                output_directory=fault_output,
                prepared_at=NOW + timedelta(minutes=6),
            )
    assert not fault_output.exists()
    assert list(fault_parent.iterdir()) == []

    retry_output = tmp_path / "retry-export"
    reporting.write_verified_governed_web_exports(
        validation=authority,
        output_directory=retry_output,
        prepared_at=NOW + timedelta(minutes=6),
    )
    assert {path.name for path in retry_output.iterdir()} == {
        "delivery-readiness.json",
        "findings.sarif",
    }


def test_validation_projection_tamper_blocks_all_downstream_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _validated_flow(tmp_path / "flow", monkeypatch)
    graph_projection = flow.validation_store.path / "governed-web-graph-admission.json"
    raw = json.loads(graph_projection.read_text(encoding="utf-8"))
    raw["admissionDigest"] = "f" * 64
    graph_projection.write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    export_output = tmp_path / "tampered-export"
    with pytest.raises((ValueError, ValidationError)):
        reporting.write_verified_governed_web_exports(
            validation=flow.validation_authority,
            output_directory=export_output,
            prepared_at=NOW + timedelta(minutes=6),
        )
    assert not export_output.exists()

    poc_output = tmp_path / "tampered-poc"
    with pytest.raises((ValueError, ValidationError)):
        reporting.write_redacted_governed_web_poc(
            validation=flow.validation_authority,
            output_directory=poc_output,
            origin=ORIGIN,
            adapter_ref="juice-shop-local/v1",
        )
    assert not poc_output.exists()


def test_governed_poc_requires_exact_lineage_is_atomic_and_one_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow = _validated_flow(tmp_path / "flow", monkeypatch)
    authority = flow.validation_authority
    generic_store = RunStore.create(tmp_path / "generic-runs", "generic-poc")
    generic_store.append_event("generic.completed", {"status": "completed"})
    generic_store.seal()

    generic_output = tmp_path / "generic-poc"
    with pytest.raises(TypeError, match="opaque validation authority"):
        reporting.write_redacted_governed_web_poc(
            validation=generic_store,  # type: ignore[arg-type]
            output_directory=generic_output,
            origin=ORIGIN,
            adapter_ref="juice-shop-local/v1",
        )
    assert not generic_output.exists()
    assert "store" not in inspect.signature(
        reporting.write_redacted_governed_web_poc
    ).parameters

    wrong_adapter_output = tmp_path / "wrong-adapter-poc"
    with pytest.raises(ValueError, match="signed adapter reference differs"):
        reporting.write_redacted_governed_web_poc(
            validation=authority,
            output_directory=wrong_adapter_output,
            origin=ORIGIN,
            adapter_ref="attacker/unsigned-ref",
        )
    assert not wrong_adapter_output.exists()

    poc_output = tmp_path / "governed-poc"
    manifest = reporting.write_redacted_governed_web_poc(
        validation=authority,
        output_directory=poc_output,
        origin=ORIGIN,
        adapter_ref="juice-shop-local/v1",
    )
    evidence = flow.promotion.promotion.execution_evidence
    assert manifest.campaign_id == evidence.campaign_id
    assert manifest.adapter_digest == evidence.adapter_digest
    assert manifest.source_assessment_root_digest == evidence.source_root_digest
    assert manifest.validation_assessment_root_digest == evidence.validation_root_digest
    assert manifest.promotion_digest == flow.promotion.promotion.promotion_digest
    assert manifest.graph_admission_digest == flow.graph_admission.admission.admission_digest
    assert manifest.validation_root_digest == authority.final_root_digest

    with pytest.raises(AttributeError, match="immutable"):
        authority._poc_consumed = False
    second_output = tmp_path / "second-poc"
    with pytest.raises(ValueError, match="already consumed"):
        reporting.write_redacted_governed_web_poc(
            validation=authority,
            output_directory=second_output,
            origin=ORIGIN,
            adapter_ref="juice-shop-local/v1",
        )
    assert not second_output.exists()

    readme_path = poc_output / manifest.readme_path
    readme_path.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="differs from its validated lineage"):
        reporting.load_verified_redacted_governed_web_poc_manifest(
            poc_output / "poc/manifest.json",
            expected=manifest,
            bundle_root=poc_output,
        )
    readme_path.write_text(
        reporting._render_redacted_governed_web_poc_readme(),
        encoding="utf-8",
    )
    script_path = poc_output / manifest.script_path
    script_path.chmod(0o600)
    with pytest.raises(ValueError, match="differs from its validated lineage"):
        reporting.load_verified_redacted_governed_web_poc_manifest(
            poc_output / "poc/manifest.json",
            expected=manifest,
            bundle_root=poc_output,
        )
