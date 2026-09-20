from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Literal

import pytest
from pydantic import JsonValue, ValidationError

import pajin.web_assessment.campaign as campaign_module
from pajin.capabilities.activation import ExistingModeCapabilityActivationSet
from pajin.capabilities.web_browser_assessment import (
    WEB_BROWSER_ASSESSMENT_METHODS,
    WEB_BROWSER_ASSESSMENT_ORIGIN,
    WebBrowserAssessmentTool,
    WebBrowserProvisionedAccountReceipt,
    registered_web_browser_assessment_plan,
    web_browser_assessment_capability_bundle,
)
from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import CampaignManifest
from pajin.graph.authority import ActionPermit
from pajin.runtime.store import RunIntegrityVerification
from pajin.tools.base import ToolRegistry
from pajin.web_assessment.campaign import (
    LocalWebAssessmentCampaignDraft,
    LocalWebAssessmentCampaignPreparation,
    LocalWebAssessmentCampaignResult,
    LocalWebAssessmentRunReference,
    build_local_web_assessment_campaign_draft,
    local_web_assessment_run_reference,
    prepare_local_web_assessment_campaign,
    reconcile_local_web_assessment_runs,
)
from pajin.web_assessment.diagnostics import build_attack_paths
from pajin.web_assessment.models import (
    AssessmentIssue,
    BrowserPageEvidence,
    BrowserSessionSummary,
    IssueCheck,
    IssueStatus,
    LocalWebAssessmentAuthorization,
    LocalWebAssessmentResult,
    ProbeTrial,
    RequestEvidence,
    WebAssessmentPlan,
    issue_observation,
)
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.verification import VerifiedLocalWebAssessmentSourceIntegrity

NOW = datetime(2026, 9, 14, 3, 0, tzinfo=UTC)


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _authorization(
    index: int,
) -> tuple[WebAssessmentPlan, LocalWebAssessmentAuthorization]:
    plan = juice_shop_plan(WEB_BROWSER_ASSESSMENT_ORIGIN)
    authorization = LocalWebAssessmentAuthorization(
        plan_digest=plan.plan_digest,
        origin=plan.origin,
        approved_at=NOW - timedelta(minutes=5) + timedelta(seconds=index),
        expires_at=NOW + timedelta(minutes=20, seconds=index),
    )
    return plan, authorization


def _requests(count: int = 18) -> tuple[RequestEvidence, ...]:
    return tuple(
        RequestEvidence(
            evidence_id=f"http-{index}-{_digest(f'evidence-{index}')[:8]}",
            phase="campaign-test",
            method="GET",
            path=f"/campaign-test/{index}",
            request_sha256=_digest(f"request-{index}"),
            status=200,
            response_sha256=_digest(f"response-{index}"),
            response_bytes=index,
            media_type="application/json",
        )
        for index in range(1, count + 1)
    )


def _issue(
    check: IssueCheck,
    *,
    reproduced: bool,
    evidence_ids: tuple[str, ...],
) -> AssessmentIssue:
    severity: Literal["high", "medium"]
    facts: dict[str, JsonValue]
    if check == "sql-login":
        cwe, severity, evidence_count = "CWE-89", "high", 3 if reproduced else 2
        facts = {
            "trueStatus": 200 if reproduced else 401,
            "falseStatus": 401,
            "sessionMinted": reproduced,
            "objectIdentityPresent": reproduced,
            "authorizedDirectoryStatus": 200 if reproduced else None,
            "authorizedDirectoryRecordCount": 2 if reproduced else 0,
            "credentialGuessUsed": False,
        }
    elif check == "object-access":
        cwe, severity, evidence_count = "CWE-639", "high", 3
        facts = {
            "attackAndTargetObjectsDiffer": True,
            "ownObjectReturned": True,
            "targetObjectReturned": reproduced,
            "missingObjectReturned": False,
            "targetStatus": 200,
            "targetProductCount": 0 if reproduced else None,
            "targetWasDisposableAssessmentAccount": True,
        }
    else:
        cwe, severity, evidence_count = "CWE-79", "medium", 2
        facts = {
            "controlMarkerExecuted": False,
            "probeMarkerExecuted": reproduced,
            "externalTransmission": False,
        }
    first = evidence_ids[:evidence_count]
    second = evidence_ids[evidence_count : evidence_count * 2]
    trials = (
        ProbeTrial(
            check=check,
            repetition="source",
            reproduced=reproduced,
            controls_passed=True,
            evidence_ids=first,
            facts=facts,
        ),
        ProbeTrial(
            check=check,
            repetition="replay",
            reproduced=reproduced,
            controls_passed=True,
            evidence_ids=second,
            facts=facts,
        ),
    )
    status: IssueStatus = "locally-reproduced" if reproduced else "not-reproduced"
    title, observed_impact = issue_observation(check, status)
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
        status=status,
        severity=severity,
        title=title,
        observed_impact=observed_impact,
        potential_impact=f"Bounded potential impact for {check}.",
        remediation=f"Bounded remediation for {check}.",
        trials=trials,
    )


def _result(
    *,
    run_id: str,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    started_at: datetime,
    reproduced: bool,
    target_version: str = "19.2.1-campaign-test",
) -> LocalWebAssessmentResult:
    requests = _requests()
    request_ids = tuple(item.evidence_id for item in requests)
    sql_count = 6 if reproduced else 4
    sql = _issue(
        "sql-login",
        reproduced=reproduced,
        evidence_ids=request_ids[:sql_count],
    )
    object_start = sql_count
    object_access = _issue(
        "object-access",
        reproduced=reproduced,
        evidence_ids=request_ids[object_start : object_start + 6],
    )
    dom_start = object_start + 6
    dom_xss = _issue(
        "dom-xss",
        reproduced=reproduced,
        evidence_ids=request_ids[dom_start : dom_start + 4],
    )
    pages = tuple(
        BrowserPageEvidence(
            phase="authenticated-navigation",
            route=f"/#/campaign-test-{index}",
            title="Juice Shop",
            ready_selector="app-root",
            dom_sha256=_digest(f"dom-{run_id}-{index}"),
            dom_bytes=100 + index,
            screenshot_reference=f"evidence/campaign-{run_id[-8:]}-{index}.png",
            screenshot_sha256=_digest(f"screenshot-{run_id}-{index}"),
            screenshot_bytes=100 + index,
            captured_at=started_at + timedelta(seconds=index),
        )
        for index in (1, 2)
    )
    issues = (sql, object_access, dom_xss)
    return LocalWebAssessmentResult(
        run_id=run_id,
        plan_name=plan.name,
        plan_digest=plan.plan_digest,
        authorization_id=authorization.authorization_id,
        origin=plan.origin,
        target_product=plan.target_product,
        target_version=target_version,
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


def _provisioning_receipt(index: int) -> WebBrowserProvisionedAccountReceipt:
    return WebBrowserProvisionedAccountReceipt(
        accountReferenceDigest=_digest(f"account-{index}"),
        provisioningEvidenceDigest=_digest(f"provisioning-evidence-{index}"),
        issuerAuthorityDigest=_digest(f"provisioning-issuer-{index}"),
        issuedAt=NOW - timedelta(seconds=10 - index),
        expiresAt=NOW + timedelta(minutes=10, seconds=index),
    )


def _verified_source(
    *,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    result: LocalWebAssessmentResult,
    index: int,
) -> VerifiedLocalWebAssessmentSourceIntegrity:
    return VerifiedLocalWebAssessmentSourceIntegrity(
        run_path=Path(f"/synthetic/run-{index}"),
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
        report_markdown="synthetic report that is deliberately not copied into the reference",
        screenshot_references=tuple(page.screenshot_reference for page in result.browser.pages),
    )


def _run_reference(
    *,
    role: Literal["source", "validation"],
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    result: LocalWebAssessmentResult,
    index: int,
) -> LocalWebAssessmentRunReference:
    return local_web_assessment_run_reference(
        role=role,
        verified_source=_verified_source(
            plan=plan,
            authorization=authorization,
            result=result,
            index=index,
        ),
    )


def _campaign_result(
    *,
    source_reproduced: bool,
    validation_reproduced: bool,
) -> tuple[
    WebAssessmentPlan,
    LocalWebAssessmentAuthorization,
    LocalWebAssessmentAuthorization,
    LocalWebAssessmentRunReference,
    LocalWebAssessmentRunReference,
    LocalWebAssessmentCampaignResult,
]:
    plan, source_authorization = _authorization(1)
    _, validation_authorization = _authorization(2)
    source_result = _result(
        run_id="run_20260914T030010Z_11111111",
        plan=plan,
        authorization=source_authorization,
        started_at=NOW + timedelta(seconds=10),
        reproduced=source_reproduced,
    )
    validation_result = _result(
        run_id="run_20260914T030030Z_22222222",
        plan=plan,
        authorization=validation_authorization,
        started_at=NOW + timedelta(seconds=30),
        reproduced=validation_reproduced,
    )
    source = _run_reference(
        role="source",
        plan=plan,
        authorization=source_authorization,
        result=source_result,
        index=1,
    )
    validation = _run_reference(
        role="validation",
        plan=plan,
        authorization=validation_authorization,
        result=validation_result,
        index=2,
    )
    result = reconcile_local_web_assessment_runs(
        plan=plan,
        source=source,
        validation=validation,
        reconciled_at=NOW + timedelta(minutes=1),
    )
    return (
        plan,
        source_authorization,
        validation_authorization,
        source,
        validation,
        result,
    )


def test_old_core_campaign_and_post_hoc_permit_api_is_absent() -> None:
    for name in (
        "GovernedLocalWebAssessmentRunReference",
        "build_local_web_assessment_campaign_manifest",
        "governed_local_web_assessment_run_reference",
    ):
        assert not hasattr(campaign_module, name)


def test_campaign_draft_is_content_addressed_local_intent_only() -> None:
    plan, authorization = _authorization(1)
    draft = build_local_web_assessment_campaign_draft(
        plan,
        authorization,
        evaluated_at=NOW,
    )

    assert draft.draft_id == f"local-web-campaign-draft_{draft.draft_digest}"
    assert draft.source_plan == plan
    assert draft.source_plan_digest == plan.plan_digest
    assert draft.authorization_id == authorization.authorization_id
    assert draft.local_authorization_semantics == "local-assertion-not-core-approval"
    assert draft.scope_preview.allow == (plan.origin,)
    assert draft.scope_preview.deny == tuple(plan.origin + path for path in plan.deny_paths)
    assert draft.scope_preview.allowed_methods == WEB_BROWSER_ASSESSMENT_METHODS
    assert draft.scope_preview.allowed_post_paths == plan.allowed_post_paths
    assert draft.required_risk_tier == "T2"
    assert draft.fresh_action_approval_required is True
    assert draft.signed_lifecycle_activation_required is True
    assert draft.durable_action_permit_required is True
    assert draft.gateway_worker_execution_required is True
    assert draft.campaign_manifest_compiled is False
    assert draft.capability_granted is False
    assert draft.action_permit_issued is False
    assert draft.execution_authorized is False

    raw = draft.model_dump(mode="json", by_alias=True)
    assert "campaign" not in raw
    assert "campaignDigest" not in raw
    raw["draftDigest"] = _digest("tampered-draft")
    with pytest.raises(ValidationError, match="draft digest differs"):
        LocalWebAssessmentCampaignDraft.model_validate(raw)


def test_local_draft_and_registration_plan_are_not_core_authority_inputs() -> None:
    plan, authorization = _authorization(1)
    draft = build_local_web_assessment_campaign_draft(
        plan,
        authorization,
        evaluated_at=NOW,
    )
    tools = ToolRegistry()
    tools.register(WebBrowserAssessmentTool())
    bundle = web_browser_assessment_capability_bundle(tools)
    capability_plan = registered_web_browser_assessment_plan(
        bundle,
        _provisioning_receipt(1),
    )

    with pytest.raises(ValidationError):
        CampaignManifest.model_validate(draft.model_dump(mode="json", by_alias=True))
    with pytest.raises(ValidationError):
        ExistingModeCapabilityActivationSet.model_validate(
            capability_plan.profile.model_dump(mode="json", by_alias=True)
        )
    with pytest.raises(ValidationError):
        ActionPermit.model_validate(capability_plan.model_dump(mode="json", by_alias=True))


def test_campaign_draft_rejects_scope_or_authority_tamper() -> None:
    plan, authorization = _authorization(1)
    draft = build_local_web_assessment_campaign_draft(
        plan,
        authorization,
        evaluated_at=NOW,
    )
    raw = draft.model_dump(mode="json", by_alias=True)
    raw["draftId"] = ""
    raw["draftDigest"] = ""
    raw["scopePreview"]["deny"].append(plan.origin + "/not-in-the-plan")
    with pytest.raises(ValidationError, match="scope"):
        LocalWebAssessmentCampaignDraft.model_validate(raw)

    raw = draft.model_dump(mode="json", by_alias=True)
    raw["draftId"] = ""
    raw["draftDigest"] = ""
    raw["campaignManifestCompiled"] = True
    with pytest.raises(ValidationError, match="cannot assert core"):
        LocalWebAssessmentCampaignDraft.model_validate(raw)

    raw = draft.model_dump(mode="json", by_alias=True)
    raw["draftId"] = ""
    raw["draftDigest"] = ""
    raw["durableActionPermitRequired"] = False
    with pytest.raises(ValidationError, match="cannot remove"):
        LocalWebAssessmentCampaignDraft.model_validate(raw)


def test_campaign_preparation_is_only_inert_draft_and_capability_plan() -> None:
    plan, authorization = _authorization(1)
    tools = ToolRegistry()
    tools.register(WebBrowserAssessmentTool())
    bundle = web_browser_assessment_capability_bundle(tools)
    capability_plan = registered_web_browser_assessment_plan(
        bundle,
        _provisioning_receipt(1),
    )

    preparation = prepare_local_web_assessment_campaign(
        role="source",
        source_plan=plan,
        authorization=authorization,
        capability_plan=capability_plan,
        evaluated_at=NOW,
    )

    assert preparation.draft.source_plan == plan
    assert preparation.capability == capability_plan.profile.capability.capability
    assert preparation.profile == capability_plan.profile.reference()
    assert preparation.plan == capability_plan.reference()
    assert preparation.campaign_manifest_compiled is False
    assert preparation.capability_granted is False
    assert preparation.lifecycle_activated is False
    assert preparation.execution_authorized is False
    assert preparation.action_permit_issued is False
    assert preparation.gateway_dispatched is False
    assert preparation.finding_authority is False

    raw = preparation.model_dump(mode="json", by_alias=True)
    assert "campaign" not in raw
    assert "authorization" not in raw
    assert "sourcePlan" not in raw
    raw["preparationDigest"] = ""
    raw["capabilityGranted"] = True
    with pytest.raises(ValidationError, match="cannot assert core"):
        LocalWebAssessmentCampaignPreparation.model_validate(raw)


def test_run_reference_is_source_integrity_only_and_drops_unneeded_source_text() -> None:
    plan, authorization = _authorization(1)
    result = _result(
        run_id="run_20260914T030010Z_33333333",
        plan=plan,
        authorization=authorization,
        started_at=NOW + timedelta(seconds=10),
        reproduced=True,
    )
    verified = _verified_source(
        plan=plan,
        authorization=authorization,
        result=result,
        index=3,
    )
    reference = local_web_assessment_run_reference(
        role="source",
        verified_source=verified,
    )

    assert reference.source_integrity_semantics == "source-integrity-only"
    assert reference.source_integrity_verified is True
    assert reference.execution_permit_attested is False
    assert reference.independent is False
    assert reference.finding_authority is False
    assert reference.result_digest == result.result_digest
    assert reference.authorization_id == authorization.authorization_id

    raw = reference.model_dump(mode="json", by_alias=True)
    for absent in (
        "runPath",
        "reportMarkdown",
        "actionPermit",
        "approvalReceipt",
        "provisioningReceipt",
        "toolRequest",
    ):
        assert absent not in raw
    raw["rootDigest"] = _digest("tampered-root")
    with pytest.raises(ValidationError, match="reference digest differs"):
        LocalWebAssessmentRunReference.model_validate(raw)

    raw = reference.model_dump(mode="json", by_alias=True)
    raw["referenceDigest"] = ""
    raw["executionPermitAttested"] = True
    with pytest.raises(ValidationError, match="cannot assert Permit"):
        LocalWebAssessmentRunReference.model_validate(raw)


def test_run_reference_builder_rejects_invalid_or_misaligned_verified_source() -> None:
    plan, authorization = _authorization(1)
    result = _result(
        run_id="run_20260914T030010Z_44444444",
        plan=plan,
        authorization=authorization,
        started_at=NOW + timedelta(seconds=10),
        reproduced=True,
    )
    verified = _verified_source(
        plan=plan,
        authorization=authorization,
        result=result,
        index=4,
    )
    invalid_verification = verified.verification.model_copy(update={"valid": False})
    with pytest.raises(ValueError, match="source integrity"):
        local_web_assessment_run_reference(
            role="source",
            verified_source=replace(verified, verification=invalid_verification),
        )

    with pytest.raises(ValueError, match="artifact identity"):
        local_web_assessment_run_reference(
            role="source",
            verified_source=replace(
                verified,
                screenshot_references=("evidence/substituted.png",),
            ),
        )

    substituted_raw = result.model_dump(mode="json")
    substituted_raw["result_digest"] = ""
    substituted_raw["target_product"] = "Substituted Product"
    substituted_result = LocalWebAssessmentResult.model_validate(substituted_raw)
    with pytest.raises(ValueError, match="verified plan, assertion, Result"):
        local_web_assessment_run_reference(
            role="source",
            verified_source=_verified_source(
                plan=plan,
                authorization=authorization,
                result=substituted_result,
                index=5,
            ),
        )


def test_two_distinct_matching_runs_are_only_locally_corroborated() -> None:
    plan, source_auth, validation_auth, source, validation, result = _campaign_result(
        source_reproduced=True,
        validation_reproduced=True,
    )

    assert source.run_id != validation.run_id
    assert source.root_digest != validation.root_digest
    assert source.result_digest != validation.result_digest
    assert source_auth.authorization_id != validation_auth.authorization_id
    assert source.authorization_id != validation.authorization_id
    assert source.plan == validation.plan == plan
    assert result.outcome == "local-corroborated"
    assert result.reconciliation_semantics == "local-corroboration-only"
    assert all(item.outcome == "local-corroborated" for item in result.claim_reconciliations)
    assert all(item.outcome == "local-corroborated" for item in result.attack_path_reconciliations)
    assert result.local_reconciliation_only is True
    assert result.campaign_manifest_compiled is False
    assert result.execution_permit_attested is False
    assert result.web_executor_attested is False
    assert result.target_attested is False
    assert result.independent_execution_attested is False
    assert result.finding_authority is False
    assert result.sarif_export_authorized is False
    assert result.external_delivery_performed is False


def test_status_mismatch_and_matching_negative_runs_have_deterministic_outcomes() -> None:
    *_, mismatch = _campaign_result(
        source_reproduced=True,
        validation_reproduced=False,
    )
    *_, negative = _campaign_result(
        source_reproduced=False,
        validation_reproduced=False,
    )

    assert mismatch.outcome == "mismatch"
    assert all(item.outcome == "mismatch" for item in mismatch.claim_reconciliations)
    assert negative.outcome == "inconclusive"
    assert all(item.outcome == "local-corroborated" for item in negative.claim_reconciliations)
    assert all(item.outcome == "inconclusive" for item in negative.attack_path_reconciliations)


def test_reconciliation_rejects_tampered_claim_path_and_campaign_status() -> None:
    *_, result = _campaign_result(
        source_reproduced=True,
        validation_reproduced=True,
    )
    raw = result.model_dump(mode="json", by_alias=True)
    raw["resultDigest"] = ""
    raw["claimReconciliations"][0]["outcome"] = "mismatch"
    with pytest.raises(ValidationError, match="typed claim reconciliation differs"):
        LocalWebAssessmentCampaignResult.model_validate(raw)

    raw = result.model_dump(mode="json", by_alias=True)
    raw["resultDigest"] = ""
    raw["attackPathReconciliations"][0]["outcome"] = "mismatch"
    with pytest.raises(ValidationError, match="attack-path shape"):
        LocalWebAssessmentCampaignResult.model_validate(raw)

    raw = result.model_dump(mode="json", by_alias=True)
    raw["resultDigest"] = ""
    raw["outcome"] = "mismatch"
    with pytest.raises(ValidationError, match="campaign outcome differs"):
        LocalWebAssessmentCampaignResult.model_validate(raw)


def test_duplicate_run_root_result_and_authorization_ids_are_rejected() -> None:
    plan, _, _, source, validation, result = _campaign_result(
        source_reproduced=True,
        validation_reproduced=True,
    )
    duplicate = source.model_dump(mode="json", by_alias=True)
    duplicate["referenceDigest"] = ""
    duplicate["role"] = "validation"
    raw = result.model_dump(mode="json", by_alias=True)
    raw["resultDigest"] = ""
    raw["validation"] = duplicate
    with pytest.raises(ValidationError, match="distinct Run IDs"):
        LocalWebAssessmentCampaignResult.model_validate(raw)

    duplicate_root = validation.model_copy(
        update={"root_digest": source.root_digest, "reference_digest": ""}
    )
    with pytest.raises(ValidationError, match="distinct Run root digests"):
        LocalWebAssessmentCampaignResult(
            plan=plan,
            source=source,
            validation=duplicate_root,
            claimReconciliations=result.claim_reconciliations,
            attackPathReconciliations=result.attack_path_reconciliations,
            outcome=result.outcome,
            reconciledAt=result.reconciled_at,
        )

    duplicate_result = validation.model_copy(
        update={
            "result_digest": source.result_digest,
            "reference_digest": "",
        }
    )
    with pytest.raises(ValidationError, match="differs from its verified"):
        LocalWebAssessmentCampaignResult(
            plan=plan,
            source=source,
            validation=duplicate_result,
            claimReconciliations=result.claim_reconciliations,
            attackPathReconciliations=result.attack_path_reconciliations,
            outcome=result.outcome,
            reconciledAt=result.reconciled_at,
        )

    duplicate_authorization_result = _result(
        run_id="run_20260914T030050Z_77777777",
        plan=plan,
        authorization=source.authorization,
        started_at=NOW + timedelta(seconds=50),
        reproduced=True,
    )
    duplicate_authorization = _run_reference(
        role="validation",
        plan=plan,
        authorization=source.authorization,
        result=duplicate_authorization_result,
        index=7,
    )
    with pytest.raises(ValidationError, match="distinct local authorization IDs"):
        reconcile_local_web_assessment_runs(
            plan=plan,
            source=source,
            validation=duplicate_authorization,
            reconciled_at=NOW + timedelta(minutes=1),
        )


def test_reconciliation_rejects_different_target_versions() -> None:
    plan, source_authorization = _authorization(1)
    _, validation_authorization = _authorization(2)
    source_result = _result(
        run_id="run_20260914T030010Z_55555555",
        plan=plan,
        authorization=source_authorization,
        started_at=NOW + timedelta(seconds=10),
        reproduced=True,
    )
    validation_result = _result(
        run_id="run_20260914T030030Z_66666666",
        plan=plan,
        authorization=validation_authorization,
        started_at=NOW + timedelta(seconds=30),
        reproduced=True,
        target_version="19.2.2-different",
    )
    source = _run_reference(
        role="source",
        plan=plan,
        authorization=source_authorization,
        result=source_result,
        index=5,
    )
    validation = _run_reference(
        role="validation",
        plan=plan,
        authorization=validation_authorization,
        result=validation_result,
        index=6,
    )

    with pytest.raises(ValidationError, match="different target versions"):
        reconcile_local_web_assessment_runs(
            plan=plan,
            source=source,
            validation=validation,
            reconciled_at=NOW + timedelta(minutes=1),
        )


@pytest.mark.parametrize(
    "field",
    (
        "campaignManifestCompiled",
        "capabilityGranted",
        "actionPermitIssued",
        "executionAuthorized",
        "executionPermitAttested",
        "gatewayDispatched",
        "webExecutorAttested",
        "targetAttested",
        "independentExecutionAttested",
        "findingAuthority",
        "sarifExportAuthorized",
        "externalDeliveryPerformed",
    ),
)
def test_campaign_result_rejects_authority_escalation(field: str) -> None:
    *_, result = _campaign_result(
        source_reproduced=True,
        validation_reproduced=True,
    )
    raw = result.model_dump(mode="json", by_alias=True)
    raw["resultDigest"] = ""
    raw[field] = True
    with pytest.raises(ValidationError, match="cannot assert execution"):
        LocalWebAssessmentCampaignResult.model_validate(raw)
