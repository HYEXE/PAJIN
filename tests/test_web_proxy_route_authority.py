from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, tzinfo
from hashlib import sha256
from itertools import pairwise
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

import pajin.benchmark.target_recovery as target_recovery_module
from pajin.benchmark.docker_provider import (
    DockerBenchmarkProviderEvidence,
    DockerBugBountyTargetProfile,
)
from pajin.benchmark.models import BenchmarkManifest
from pajin.benchmark.scanner_baseline import ScannerBaselineMeasurementPlanAuthority
from pajin.benchmark.scanner_sarif import ZAPScannerRegistration, registered_zap_scanner
from pajin.benchmark.target_factory import (
    BenchmarkTargetCoordinate,
    BenchmarkTargetStageReceipt,
    RegisteredBenchmarkTargetFactoryAdapter,
    benchmark_target_coordinate,
)
from pajin.benchmark.target_recovery import (
    BenchmarkTargetAttempt,
    BenchmarkTargetOperation,
    BenchmarkTargetOperationJournal,
)
from pajin.capabilities.activation import capability_normalized_parameters_digest
from pajin.capabilities.lifecycle import CapabilityLifecycleRegistry, CapabilityReleaseRef
from pajin.capabilities.web_measured_validation import (
    WEB_MEASURED_VALIDATION_TARGET,
    WebMeasuredValidationCapabilityBundle,
)
from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CampaignMode,
    ToolRequest,
    ToolRiskTier,
    WeeklyTestingWindow,
    campaign_manifest_digest,
)
from pajin.graph.approval import (
    ActionApprovalAuthorization,
    ActionApprovalEnvelope,
    ActionApprovalIssuerAuthorityBinding,
    ActionApprovalReleaseRef,
    build_action_approval_consumption_receipt,
)
from pajin.graph.authority import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionPermit,
    ActionPermitAuthorization,
    ActionProposal,
    MissionEnvelope,
    action_permit_attempt_id,
)
from pajin.graph.consistency import GraphDecision, GraphDecisionKind
from pajin.graph.projection import GraphSnapshotRef
from pajin.runtime.worker import NetworkMode
from pajin.tools.base import http_target_sha256
from pajin.tools.bug_bounty import BOOLEAN_SQLI_SCENARIO, BooleanSQLiProbeTool
from pajin.tools.gateway import canonical_tool_request_digest
from pajin.workflow.web_measured_case_authority import WebMeasuredCaseAuthority
from pajin.workflow.web_proxy_route_authority import (
    SignedWebProxyRoute,
    WebProxyRouteAuthorityError,
    WebProxyRouteAuthoritySigner,
    WebProxyRouteBundle,
    WebProxyRouteRuntimePolicy,
    WebProxyRouteSigningKeyState,
    WebProxyRouteStatement,
    WebProxyRouteTargetBinding,
    WebProxyRouteTargetCleanupInvalidated,
    WebProxyRouteTrustAnchor,
    WebProxyRouteVerification,
    WebProxyRouteVerificationKey,
    load_web_proxy_route_verification,
    registered_web_proxy_route_runtime_policy,
    verify_cleanup_invalidated_web_proxy_route_history,
    verify_web_proxy_route_authority,
    web_proxy_route_public_key_base64url,
)
from pajin.workflow.web_replay_benchmark import WebAPIBenchmarkGroundTruthProfile
from tests.test_web_measured_case_authority import _case as measured_case_fixture
from tests.test_web_measured_case_authority import _profile as target_profile_fixture

CAMPAIGN_ID = "web-002-route"
RUN_ID = "run.web002.route"
TARGET_DIGEST = http_target_sha256(WEB_MEASURED_VALIDATION_TARGET)
COMPILER_DIGEST = sha256(b"web-002-route-compiler").hexdigest()
ROUTE_PRIVATE_KEY = sha256(b"web-002-route-signing-key").digest()
FALSE_MARKERS = (
    "route_materialized",
    "route_consumed",
    "proxy_attached",
    "worker_attached",
    "proxy_detached",
    "target_cleanup_observed",
    "provider_execution_authorized",
    "network_access_authorized",
    "worker_selected",
    "measurement_observed",
    "graph_write_authorized",
    "finding_authorized",
    "benchmark_validation_floor_satisfied",
    "finding_projection_authorized",
    "product_activation_authorized",
    "report_delivery_authorized",
    "execution_authorized",
)


class _DurableApprovalLookup:
    def __init__(
        self,
        authorization: ActionApprovalAuthorization | None,
        *,
        exact_keys: bool = True,
    ) -> None:
        self.authorization = authorization
        self.exact_keys = exact_keys

    def approved_authorization(
        self,
        approval_id: str,
        permit_id: str,
    ) -> ActionApprovalAuthorization | None:
        authorization = self.authorization
        if authorization is None:
            return None
        if self.exact_keys and (
            authorization.approval.approval_id != approval_id
            or authorization.action.permit.permit_id != permit_id
        ):
            return None
        return authorization.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class JournalContext:
    journal: BenchmarkTargetOperationJournal
    attempt: BenchmarkTargetAttempt
    reset_operation: BenchmarkTargetOperation
    reset_receipt: BenchmarkTargetStageReceipt
    reset_evidence: DockerBenchmarkProviderEvidence
    isolation_operation: BenchmarkTargetOperation
    execution_operation: BenchmarkTargetOperation
    isolation_receipt: BenchmarkTargetStageReceipt
    isolation_evidence: DockerBenchmarkProviderEvidence
    issued_at: datetime


@dataclass(frozen=True, slots=True)
class RouteContext:
    signer: WebProxyRouteAuthoritySigner
    trust_anchor: WebProxyRouteTrustAnchor
    measured_case: WebMeasuredCaseAuthority
    capability_bundle: WebMeasuredValidationCapabilityBundle
    capability_lifecycle: CapabilityLifecycleRegistry
    capability_release: CapabilityReleaseRef
    private_ground_truth_profile: WebAPIBenchmarkGroundTruthProfile
    scanner_plan: ScannerBaselineMeasurementPlanAuthority
    scanner_registration: ZAPScannerRegistration
    runtime_policy: WebProxyRouteRuntimePolicy
    target_adapter: RegisteredBenchmarkTargetFactoryAdapter
    target_profile: DockerBugBountyTargetProfile
    coordinate: BenchmarkTargetCoordinate
    target_journal: BenchmarkTargetOperationJournal
    target_attempt_id: str
    attempt: BenchmarkTargetAttempt
    reset_operation: BenchmarkTargetOperation
    reset_receipt: BenchmarkTargetStageReceipt
    reset_evidence: DockerBenchmarkProviderEvidence
    isolation_operation: BenchmarkTargetOperation
    execution_operation: BenchmarkTargetOperation
    isolation_receipt: BenchmarkTargetStageReceipt
    isolation_evidence: DockerBenchmarkProviderEvidence
    campaign: CampaignManifest
    approval_store: _DurableApprovalLookup
    authorization: ActionApprovalAuthorization
    request: ToolRequest
    issued_at: datetime


def _operation(
    attempt: BenchmarkTargetAttempt,
    stage: str,
    ordinal: int,
) -> BenchmarkTargetOperation:
    return BenchmarkTargetOperation(
        attemptId=attempt.attempt_id,
        attemptDigest=attempt.attempt_digest,
        adapterDigest=attempt.adapter_digest,
        coordinateDigest=attempt.coordinate_digest,
        fence=attempt.fence,
        stage=stage,
        ordinal=ordinal,
    )


def _journal_clock(instants: tuple[datetime, ...]) -> type[datetime]:
    timeline = iter(instants)

    class JournalClock(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:
            instant = next(timeline)
            return instant.replace(tzinfo=None) if tz is None else instant.astimezone(tz)

    return JournalClock


def _seed_target_journal(
    path: Path,
    *,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    coordinate: BenchmarkTargetCoordinate,
    target_profile: DockerBugBountyTargetProfile,
    reset_receipt_ordinal: int = 1,
    reset_environment_id: str = "environment.web002",
    isolation_environment_id: str = "environment.web002",
    reset_completion_offset: timedelta = timedelta(0),
    record_times: tuple[datetime, ...] | None = None,
) -> JournalContext:
    journal_datetime = target_recovery_module.datetime
    clock = journal_datetime if record_times is None else _journal_clock(record_times)
    with patch.object(target_recovery_module, "datetime", clock):
        journal = BenchmarkTargetOperationJournal(path)
        attempt = journal.begin_attempt(adapter, coordinate)
        reset_operation = _operation(attempt, "reset", 1)
        reset_receipt_operation = _operation(attempt, "reset", reset_receipt_ordinal)
        isolation_operation = _operation(attempt, "isolation", 1)
        execution_operation = _operation(attempt, "execution", 1)

        journal.append_intent(reset_operation)
        reset_intent_at = journal.current_open_attempt(attempt.attempt_id)[4][-1].occurred_at
        reset_evidence = DockerBenchmarkProviderEvidence(
            adapterDigest=adapter.adapter_digest,
            coordinateDigest=coordinate.coordinate_digest,
            operationId=reset_receipt_operation.operation_id,
            operationDigest=reset_receipt_operation.operation_digest,
            fence=attempt.fence,
            stage="reset",
            environmentId=reset_environment_id,
            dockerServerVersion="27.3.1",
            targetImageId=target_profile.target_image_id,
            workerImageId=target_profile.worker_image_id,
            resourcesAbsent=True,
            observedAt=reset_intent_at,
        )
        reset_receipt = BenchmarkTargetStageReceipt(
            adapterDigest=adapter.adapter_digest,
            coordinateDigest=coordinate.coordinate_digest,
            stage="reset",
            operationId=reset_receipt_operation.operation_id,
            environmentId=reset_environment_id,
            status="succeeded",
            startedAt=reset_intent_at,
            completedAt=reset_intent_at + reset_completion_offset,
            providerEvidenceDigest=reset_evidence.evidence_digest,
        )
        journal.append_receipt(reset_receipt_operation, reset_receipt)

        journal.append_intent(isolation_operation)
        isolation_intent_at = journal.current_open_attempt(attempt.attempt_id)[4][-1].occurred_at
        isolation_evidence = DockerBenchmarkProviderEvidence(
            adapterDigest=adapter.adapter_digest,
            coordinateDigest=coordinate.coordinate_digest,
            operationId=isolation_operation.operation_id,
            operationDigest=isolation_operation.operation_digest,
            fence=attempt.fence,
            stage="isolation",
            environmentId=isolation_environment_id,
            isolationId="isolation.web002",
            dockerServerVersion="27.3.1",
            targetImageId=target_profile.target_image_id,
            workerImageId=target_profile.worker_image_id,
            targetContainerId="7" * 64,
            networkId="8" * 64,
            networkInternal=True,
            publishedPortCount=0,
            networkContainerCount=1,
            targetHealthy=True,
            observedAt=isolation_intent_at,
        )
        isolation_receipt = BenchmarkTargetStageReceipt(
            adapterDigest=adapter.adapter_digest,
            coordinateDigest=coordinate.coordinate_digest,
            stage="isolation",
            operationId=isolation_operation.operation_id,
            environmentId=isolation_evidence.environment_id,
            isolationId=isolation_evidence.isolation_id,
            status="succeeded",
            startedAt=isolation_intent_at,
            completedAt=isolation_intent_at,
            providerEvidenceDigest=isolation_evidence.evidence_digest,
        )
        journal.append_receipt(isolation_operation, isolation_receipt)

        journal.append_intent(execution_operation)
        execution_intent_at = journal.current_open_attempt(attempt.attempt_id)[4][-1].occurred_at
    return JournalContext(
        journal=journal,
        attempt=attempt,
        reset_operation=reset_operation,
        reset_receipt=reset_receipt,
        reset_evidence=reset_evidence,
        isolation_operation=isolation_operation,
        execution_operation=execution_operation,
        isolation_receipt=isolation_receipt,
        isolation_evidence=isolation_evidence,
        issued_at=execution_intent_at + timedelta(microseconds=1),
    )


def _campaign(at: datetime) -> CampaignManifest:
    return CampaignManifest(
        apiVersion="pajin.dev/v1alpha1",
        kind="Campaign",
        metadata={"name": CAMPAIGN_ID},
        spec={
            "mode": CampaignMode.BUG_BOUNTY,
            "autonomy": AutonomyLevel.SUPERVISED,
            "authorization": {
                "approvedBy": "benchmark-owner",
                "approvedAt": at - timedelta(hours=1),
                "expiresAt": at + timedelta(hours=1),
                "evidence": "synthetic-local-benchmark-approval",
            },
            "targets": [
                {
                    "type": "http-api",
                    "id": "boolean-sqli-lab",
                    "endpoint": WEB_MEASURED_VALIDATION_TARGET,
                }
            ],
            "scope": {"allow": [WEB_MEASURED_VALIDATION_TARGET], "deny": []},
            "objectives": ["Measure the fixed synthetic Boolean SQLi case"],
            "rulesOfEngagement": {
                "maxToolRiskTier": ToolRiskTier.T2,
                "allowedMethods": ["GET"],
                "allowPrivateNetworks": True,
            },
            "budgets": {
                "durationSeconds": 300,
                "maxCostUsd": 0,
                "maxAgents": 1,
                "maxSpawnDepth": 0,
                "maxToolCalls": 1,
                "maxModelCalls": 0,
                "maxModelTokens": 0,
            },
        },
    )


def _request() -> ToolRequest:
    return ToolRequest(
        request_id="tool_web002_route",
        agent_id="agent.web002",
        tool_id=BooleanSQLiProbeTool.spec.tool_id,
        target=WEB_MEASURED_VALIDATION_TARGET,
        method="GET",
        arguments={"scenario_id": BOOLEAN_SQLI_SCENARIO},
    )


def _approved_authorization(
    measured_case: WebMeasuredCaseAuthority,
    campaign: CampaignManifest,
    request: ToolRequest,
    *,
    at: datetime,
) -> ActionApprovalAuthorization:
    capability = measured_case.profile.action_capability
    capability_ref = capability.reference()
    envelope = MissionEnvelope(
        campaignId=campaign.metadata.name,
        runId=RUN_ID,
        profileId=measured_case.profile.profile_id,
        profileVersion=measured_case.profile.profile_version,
        profileDigest=measured_case.profile.profile_digest,
        compilerId="pajin.web-002.route-compiler",
        compilerVersion="1.0.0",
        compilerDigest=COMPILER_DIGEST,
        sourceCampaignDigest=campaign_manifest_digest(campaign),
        allowedCapabilities=(capability_ref,),
        allowedTargetDigests=(TARGET_DIGEST,),
        maxRiskTier=ToolRiskTier.T2,
        budget=ActionBudgetLimit(
            toolCallLimit=1,
            requestUnitLimit=3,
            costLimitMicrousd=0,
        ),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=at - timedelta(minutes=10),
        notBefore=at - timedelta(minutes=5),
        expiresAt=at + timedelta(minutes=10),
    )
    snapshot = GraphSnapshotRef(
        snapshotId="graph-snapshot_" + "1" * 64,
        snapshotDigest="2" * 64,
        campaignId=envelope.campaign_id,
        revision=0,
        projectionDigest="3" * 64,
    )
    decision = GraphDecision(
        campaignId=envelope.campaign_id,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest="4" * 64,
        snapshot=snapshot,
        actorId="pajin.graph.web002-planner",
        actorDigest="5" * 64,
        createdAt=at - timedelta(minutes=4),
    )
    reservation = ActionBudgetReservation(requestUnits=3, costMicrousd=0)
    proposal = ActionProposal(
        campaignId=envelope.campaign_id,
        runId=envelope.run_id,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=decision.snapshot,
        proposerId="pajin.graph.web002-planner",
        proposerDigest="6" * 64,
        capability=capability_ref,
        targetDigest=TARGET_DIGEST,
        requestId=request.request_id,
        requestDigest=canonical_tool_request_digest(request),
        normalizedParametersDigest=capability_normalized_parameters_digest(request.arguments),
        riskTier=capability.risk_tier,
        reservation=reservation,
        createdAt=at - timedelta(minutes=3),
    )
    release = measured_case.capability_release
    approval = ActionApprovalEnvelope(
        issuer=ActionApprovalIssuerAuthorityBinding(
            authorityId="deployment.web002.operator-approval",
            authorityVersion="1.0.0",
            implementationType="tests.web002.StaticApprovalIssuer",
            contextDigest="7" * 64,
        ),
        requestedBy="principal.web002-planner",
        approvedBy="principal.web002-operator",
        campaignId=envelope.campaign_id,
        campaignDigest=campaign_manifest_digest(campaign),
        runId=envelope.run_id,
        missionEnvelope=envelope,
        sourceIntentDigest=decision.decision_payload_digest,
        activationSetDigest="8" * 64,
        release=ActionApprovalReleaseRef(
            releaseId=release.release_id,
            releaseDigest=release.release_digest,
            capabilityId=capability_ref.capability_id,
            capabilityVersion=capability_ref.capability_version,
            capabilityDigest=capability_ref.definition_digest,
        ),
        graphDecision=decision,
        proposal=proposal,
        expectedActionPermitId=action_permit_attempt_id(envelope, proposal, decision),
        sideEffectClass="read-only",
        cleanupRequired=False,
        reservation=reservation,
        approvedAt=at - timedelta(minutes=2),
        notBefore=at - timedelta(seconds=90),
        expiresAt=at + timedelta(minutes=5),
    )
    permit = ActionPermit(
        campaignId=envelope.campaign_id,
        runId=envelope.run_id,
        compilerId=envelope.compiler_id,
        compilerVersion=envelope.compiler_version,
        compilerDigest=envelope.compiler_digest,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        proposalId=proposal.proposal_id,
        proposalDigest=proposal.proposal_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=decision.snapshot,
        capability=capability_ref,
        targetDigest=TARGET_DIGEST,
        requestId=request.request_id,
        requestDigest=canonical_tool_request_digest(request),
        normalizedParametersDigest=capability_normalized_parameters_digest(request.arguments),
        reservation=reservation,
        issuedAt=at - timedelta(minutes=1),
        consumedAt=at - timedelta(seconds=30),
        expiresAt=at + timedelta(minutes=4),
    )
    receipt = build_action_approval_consumption_receipt(approval, permit)
    return ActionApprovalAuthorization(
        approval=approval,
        action=ActionPermitAuthorization(permit=permit, newlyConsumed=False),
        receipt=receipt,
    )


@pytest.fixture(scope="module")
def route_context(tmp_path_factory: pytest.TempPathFactory) -> RouteContext:
    measured_case, capability_bundle, lifecycle, private_profile, target_adapter = (
        measured_case_fixture()
    )
    target_profile = target_profile_fixture()
    manifest = measured_case.scanner_plan.manifest
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    journal = _seed_target_journal(
        tmp_path_factory.mktemp("web-proxy-route") / "target-journal.sqlite3",
        adapter=target_adapter,
        coordinate=coordinate,
        target_profile=target_profile,
    )
    campaign = _campaign(journal.issued_at)
    request = _request()
    authorization = _approved_authorization(
        measured_case,
        campaign,
        request,
        at=journal.issued_at,
    )
    runtime_policy = registered_web_proxy_route_runtime_policy(
        deployment_id="deployment.web002",
        gateway_policy_id="gateway-policy.web002",
        claim_ledger_identity_digest="d" * 64,
        gateway_policy_version="1.0.0",
        gateway_policy_digest="9" * 64,
        worker_backend_id="docker-worker-backend.web002",
        worker_backend_version="1.0.0",
        worker_backend_digest="a" * 64,
        worker_image_id="sha256:" + "b" * 64,
        proxy_image_id="sha256:" + "c" * 64,
    )
    key = WebProxyRouteVerificationKey(
        keyId="web002.route.key",
        publicKeyBase64url=web_proxy_route_public_key_base64url(ROUTE_PRIVATE_KEY),
        state=WebProxyRouteSigningKeyState.ACTIVE,
        notBefore=journal.issued_at - timedelta(days=1),
    )
    trust_anchor = WebProxyRouteTrustAnchor(
        trustDomain="pajin.web-002.proxy-route",
        issuer="pajin.deployment",
        deploymentId=runtime_policy.deployment_id,
        keys=(key,),
    )
    signer = WebProxyRouteAuthoritySigner.from_private_key_bytes(
        key=key,
        private_key=ROUTE_PRIVATE_KEY,
        trust_anchor=trust_anchor,
    )
    return RouteContext(
        signer=signer,
        trust_anchor=trust_anchor,
        measured_case=measured_case,
        capability_bundle=capability_bundle,
        capability_lifecycle=lifecycle,
        capability_release=measured_case.capability_release,
        private_ground_truth_profile=private_profile,
        scanner_plan=measured_case.scanner_plan,
        scanner_registration=measured_case.scanner_registration,
        runtime_policy=runtime_policy,
        target_adapter=target_adapter,
        target_profile=target_profile,
        coordinate=coordinate,
        target_journal=journal.journal,
        target_attempt_id=journal.attempt.attempt_id,
        attempt=journal.attempt,
        reset_operation=journal.reset_operation,
        reset_receipt=journal.reset_receipt,
        reset_evidence=journal.reset_evidence,
        isolation_operation=journal.isolation_operation,
        execution_operation=journal.execution_operation,
        isolation_receipt=journal.isolation_receipt,
        isolation_evidence=journal.isolation_evidence,
        campaign=campaign,
        approval_store=_DurableApprovalLookup(authorization),
        authorization=authorization,
        request=request,
        issued_at=journal.issued_at,
    )


def _issue(context: RouteContext, **overrides: object) -> WebProxyRouteBundle:
    inputs: dict[str, object] = {
        "measured_case": context.measured_case,
        "capability_bundle": context.capability_bundle,
        "capability_lifecycle": context.capability_lifecycle,
        "capability_release": context.capability_release,
        "private_ground_truth_profile": context.private_ground_truth_profile,
        "scanner_plan": context.scanner_plan,
        "scanner_registration": context.scanner_registration,
        "runtime_policy": context.runtime_policy,
        "target_profile": context.target_profile,
        "target_journal": context.target_journal,
        "target_attempt_id": context.target_attempt_id,
        "isolation_evidence": context.isolation_evidence,
        "campaign": context.campaign,
        "approval_store": context.approval_store,
        "approval_id": context.authorization.approval.approval_id,
        "permit_id": context.authorization.action.permit.permit_id,
        "request": context.request,
        "route_nonce": "d" * 32,
        "issued_at": context.issued_at,
        "not_before": context.issued_at,
        "expires_at": context.issued_at + timedelta(minutes=2),
    }
    inputs.update(overrides)
    return context.signer.issue(**inputs)  # type: ignore[arg-type]


def _verification_inputs(context: RouteContext) -> dict[str, object]:
    return {
        "trust_anchor": context.trust_anchor,
        "measured_case": context.measured_case,
        "capability_bundle": context.capability_bundle,
        "capability_lifecycle": context.capability_lifecycle,
        "capability_release": context.capability_release,
        "private_ground_truth_profile": context.private_ground_truth_profile,
        "scanner_plan": context.scanner_plan,
        "scanner_registration": context.scanner_registration,
        "runtime_policy": context.runtime_policy,
        "target_profile": context.target_profile,
        "target_journal": context.target_journal,
        "target_attempt_id": context.target_attempt_id,
        "isolation_evidence": context.isolation_evidence,
        "campaign": context.campaign,
        "approval_store": context.approval_store,
        "approval_id": context.authorization.approval.approval_id,
        "permit_id": context.authorization.action.permit.permit_id,
        "request": context.request,
        "evaluated_at": context.issued_at + timedelta(seconds=30),
    }


def _verify(
    context: RouteContext,
    bundle: WebProxyRouteBundle,
    **overrides: object,
) -> WebProxyRouteVerification:
    inputs = _verification_inputs(context)
    inputs.update(overrides)
    return verify_web_proxy_route_authority(bundle, **inputs)  # type: ignore[arg-type]


def _verify_cleanup_history(
    context: RouteContext,
    bundle: WebProxyRouteBundle,
    **overrides: object,
) -> None:
    inputs = _verification_inputs(context)
    inputs.update(overrides)
    verify_cleanup_invalidated_web_proxy_route_history(  # type: ignore[arg-type]
        bundle,
        **inputs,
    )


def _reload(
    context: RouteContext,
    verification: WebProxyRouteVerification,
    bundle: WebProxyRouteBundle,
    **overrides: object,
) -> WebProxyRouteVerification:
    inputs = _verification_inputs(context)
    inputs.update(overrides)
    return load_web_proxy_route_verification(  # type: ignore[arg-type]
        verification,
        bundle,
        **inputs,
    )


def _with_fresh_journal(
    context: RouteContext,
    path: Path,
    *,
    reset_receipt_ordinal: int = 1,
    reset_environment_id: str = "environment.web002",
    isolation_environment_id: str = "environment.web002",
    reset_completion_offset: timedelta = timedelta(0),
    record_times: tuple[datetime, ...] | None = None,
) -> RouteContext:
    if record_times is None:
        base = context.issued_at - timedelta(minutes=1)
        record_times = tuple(base + timedelta(microseconds=index) for index in range(6))
    journal = _seed_target_journal(
        path,
        adapter=context.target_adapter,
        coordinate=context.coordinate,
        target_profile=context.target_profile,
        reset_receipt_ordinal=reset_receipt_ordinal,
        reset_environment_id=reset_environment_id,
        isolation_environment_id=isolation_environment_id,
        reset_completion_offset=reset_completion_offset,
        record_times=record_times,
    )
    assert journal.isolation_receipt.completed_at <= context.issued_at
    return replace(
        context,
        target_journal=journal.journal,
        target_attempt_id=journal.attempt.attempt_id,
        attempt=journal.attempt,
        reset_operation=journal.reset_operation,
        reset_receipt=journal.reset_receipt,
        reset_evidence=journal.reset_evidence,
        isolation_operation=journal.isolation_operation,
        execution_operation=journal.execution_operation,
        isolation_receipt=journal.isolation_receipt,
        isolation_evidence=journal.isolation_evidence,
    )


def _with_campaign(context: RouteContext, campaign: CampaignManifest) -> RouteContext:
    authorization = _approved_authorization(
        context.measured_case,
        campaign,
        context.request,
        at=context.issued_at,
    )
    return replace(
        context,
        campaign=campaign,
        approval_store=_DurableApprovalLookup(authorization),
        authorization=authorization,
    )


def _rebuild_approval(
    approval: ActionApprovalEnvelope,
    **updates: object,
) -> ActionApprovalEnvelope:
    raw = approval.model_dump(mode="python", by_alias=True)
    raw.pop("approvalId")
    raw.pop("approvalDigest")
    raw.update(updates)
    return ActionApprovalEnvelope.model_validate(raw)


def _rebuild_permit(permit: ActionPermit, **updates: object) -> ActionPermit:
    raw = permit.model_dump(mode="python", by_alias=True)
    raw.pop("permitId")
    raw.pop("permitDigest")
    raw.pop("dispatchId")
    raw.update(updates)
    return ActionPermit.model_validate(raw)


def _rebuild_verification(
    verification: WebProxyRouteVerification,
    **updates: object,
) -> WebProxyRouteVerification:
    raw = verification.model_dump(mode="python", by_alias=True)
    raw.pop("verificationId")
    raw.pop("verificationDigest")
    raw.update(updates)
    return WebProxyRouteVerification.model_validate(raw)


def test_signed_route_issues_verifies_and_reloads_all_durable_bindings(
    route_context: RouteContext,
) -> None:
    bundle = _issue(route_context)
    verification = _verify(route_context, bundle)
    reloaded = _reload(route_context, verification, bundle)
    statement = bundle.route.statement
    authorization = route_context.authorization

    assert reloaded == verification
    assert verification.route_id == statement.route_id
    assert verification.route_digest == statement.route_digest
    assert verification.bundle_digest == bundle.digest
    assert verification.signature_verified is True
    assert verification.current_fence_verified is True
    assert verification.approval_consumption_verified is True
    assert verification.target_journal_head_verified is True
    assert statement.approval_id == authorization.approval.approval_id
    assert statement.approval_digest == authorization.approval.approval_digest
    assert statement.approval_receipt_id == authorization.receipt.receipt_id
    assert statement.approval_receipt_digest == authorization.receipt.receipt_digest
    assert statement.permit_id == authorization.action.permit.permit_id
    assert statement.permit_digest == authorization.action.permit.permit_digest
    assert statement.target.attempt_id == route_context.target_attempt_id
    assert statement.target.isolation_operation_id == route_context.isolation_operation.operation_id
    assert statement.target.execution_operation_id == route_context.execution_operation.operation_id
    assert statement.target.isolation_receipt_id == route_context.isolation_receipt.receipt_id
    assert (
        route_context.reset_operation.ordinal,
        route_context.isolation_operation.ordinal,
        route_context.execution_operation.ordinal,
    ) == (1, 1, 1)
    assert statement.campaign_digest == campaign_manifest_digest(route_context.campaign)
    assert statement.request_digest == canonical_tool_request_digest(route_context.request)
    assert all(getattr(statement, field) is False for field in FALSE_MARKERS)
    assert all(getattr(verification, field) is False for field in FALSE_MARKERS)


def test_reissued_route_converges_on_one_consumption_slot(
    route_context: RouteContext,
) -> None:
    first = _issue(route_context, route_nonce="d" * 32)
    second = _issue(route_context, route_nonce="e" * 32)
    first_statement = first.route.statement
    second_statement = second.route.statement

    assert first_statement.consumption_slot_digest == second_statement.consumption_slot_digest
    assert (
        first_statement.worker_proxy_network_slot_digest
        != second_statement.worker_proxy_network_slot_digest
    )
    assert first_statement.route_id != second_statement.route_id
    assert first_statement.route_digest != second_statement.route_digest


def test_route_validity_is_capped_by_permit_campaign_and_testing_window(
    route_context: RouteContext,
) -> None:
    permit_expiry = route_context.authorization.action.permit.expires_at
    assert route_context.issued_at < permit_expiry
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(
            route_context,
            expires_at=permit_expiry + timedelta(microseconds=1),
        )

    campaign_authorization = route_context.campaign.spec.authorization.model_copy(
        update={"expires_at": route_context.issued_at + timedelta(minutes=1)}
    )
    campaign = route_context.campaign.model_copy(
        update={
            "spec": route_context.campaign.spec.model_copy(
                update={"authorization": campaign_authorization}
            )
        }
    )
    campaign_context = _with_campaign(route_context, campaign)
    assert campaign.spec.authorization.is_active(route_context.issued_at)
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(campaign_context)

    window_start = route_context.issued_at - timedelta(minutes=1)
    window_end = route_context.issued_at + timedelta(minutes=1)
    window = WeeklyTestingWindow(
        days={window_start.strftime("%A").lower()},
        startTime=window_start.timetz().replace(tzinfo=None),
        endTime=window_end.timetz().replace(tzinfo=None),
        timezone="UTC",
    )
    rules = route_context.campaign.spec.rules_of_engagement.model_copy(
        update={"testing_windows": [window]}
    )
    campaign = route_context.campaign.model_copy(
        update={
            "spec": route_context.campaign.spec.model_copy(update={"rules_of_engagement": rules})
        }
    )
    window_context = _with_campaign(route_context, campaign)
    route_expiry = route_context.issued_at + timedelta(minutes=2)
    assert window.is_active(route_context.issued_at)
    assert not window.is_active(route_expiry - timedelta(microseconds=1))
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(window_context, expires_at=route_expiry)


def test_verification_reload_rejects_self_consistent_forged_artifact(
    route_context: RouteContext,
) -> None:
    bundle = _issue(route_context)
    verification = _verify(route_context, bundle)
    forged = _rebuild_verification(verification, bundleDigest="e" * 64)

    assert forged.verification_id != verification.verification_id
    assert forged.verification_digest != verification.verification_digest
    with pytest.raises(WebProxyRouteAuthorityError, match="reload failed closed"):
        _reload(route_context, forged, bundle)


def test_route_fails_closed_on_expiry_signature_key_and_route_revocation(
    route_context: RouteContext,
) -> None:
    bundle = _issue(route_context)

    with pytest.raises(WebProxyRouteAuthorityError, match="verification failed closed"):
        _verify(
            route_context,
            bundle,
            evaluated_at=bundle.route.statement.expires_at,
        )

    signature = bundle.route.signature_base64url
    substituted_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    forged_bundle = WebProxyRouteBundle(
        route=SignedWebProxyRoute(
            keyId=bundle.route.key_id,
            statement=bundle.route.statement,
            signatureBase64url=substituted_signature,
        )
    )
    with pytest.raises(WebProxyRouteAuthorityError, match="verification failed closed"):
        _verify(route_context, forged_bundle)

    revoked_key = route_context.signer.key.model_copy(
        update={
            "state": WebProxyRouteSigningKeyState.REVOKED,
            "revoked_at": route_context.issued_at - timedelta(seconds=1),
        }
    )
    revoked_key_anchor = WebProxyRouteTrustAnchor(
        trustDomain=route_context.trust_anchor.trust_domain,
        issuer=route_context.trust_anchor.issuer,
        deploymentId=route_context.trust_anchor.deployment_id,
        keys=(revoked_key,),
    )
    with pytest.raises(WebProxyRouteAuthorityError, match="not currently usable"):
        _verify(route_context, bundle, trust_anchor=revoked_key_anchor)

    revoked_route_anchor = WebProxyRouteTrustAnchor(
        trustDomain=route_context.trust_anchor.trust_domain,
        issuer=route_context.trust_anchor.issuer,
        deploymentId=route_context.trust_anchor.deployment_id,
        keys=route_context.trust_anchor.keys,
        revokedRouteDigests=(bundle.route.statement.route_digest,),
    )
    with pytest.raises(WebProxyRouteAuthorityError, match="verification failed closed"):
        _verify(route_context, bundle, trust_anchor=revoked_route_anchor)


def test_route_rejects_missing_or_foreign_approval_and_exact_context_drift(
    route_context: RouteContext,
) -> None:
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(route_context, approval_store=_DurableApprovalLookup(None))

    authorization = route_context.authorization
    foreign_approval = _rebuild_approval(
        authorization.approval,
        requestedBy="principal.foreign-planner",
    )
    foreign_receipt = build_action_approval_consumption_receipt(
        foreign_approval,
        authorization.action.permit,
    )
    foreign_authorization = authorization.model_copy(update={"receipt": foreign_receipt})
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(
            route_context,
            approval_store=_DurableApprovalLookup(
                foreign_authorization,
                exact_keys=False,
            ),
        )

    newly_consumed = authorization.model_copy(
        update={"action": authorization.action.model_copy(update={"newly_consumed": True})}
    )
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(
            route_context,
            approval_store=_DurableApprovalLookup(newly_consumed),
        )

    bundle = _issue(route_context)
    foreign_campaign = route_context.campaign.model_copy(
        update={
            "spec": route_context.campaign.spec.model_copy(
                update={"objectives": ["Substituted objective"]}
            )
        }
    )
    expanded_scope = route_context.campaign.model_copy(
        update={
            "spec": route_context.campaign.spec.model_copy(
                update={
                    "scope": route_context.campaign.spec.scope.model_copy(
                        update={
                            "allow": [
                                WEB_MEASURED_VALIDATION_TARGET,
                                "http://target:8080/other",
                            ]
                        }
                    )
                }
            )
        }
    )
    foreign_request = route_context.request.model_copy(update={"agent_id": "agent.foreign"})
    for field, value in (
        ("campaign", foreign_campaign),
        ("campaign", expanded_scope),
        ("request", foreign_request),
    ):
        with pytest.raises(WebProxyRouteAuthorityError, match="verification failed closed"):
            _verify(route_context, bundle, **{field: value})


def test_public_api_excludes_bare_authority_and_rechecks_measured_predecessors(
    route_context: RouteContext,
) -> None:
    forbidden = {
        "target_adapter",
        "coordinate",
        "attempt",
        "isolation_operation",
        "execution_operation",
        "isolation_receipt",
        "active_fence",
        "target_cleanup_observed",
        "envelope",
        "permit",
    }
    issue_parameters = set(inspect.signature(WebProxyRouteAuthoritySigner.issue).parameters)
    verify_parameters = set(inspect.signature(verify_web_proxy_route_authority).parameters)
    assert forbidden.isdisjoint(issue_parameters)
    assert forbidden.isdisjoint(verify_parameters)

    forged_permit = _rebuild_permit(
        route_context.authorization.action.permit,
        targetDigest="e" * 64,
    )
    assert forged_permit.permit_digest != route_context.authorization.action.permit.permit_digest
    with pytest.raises(TypeError, match="unexpected keyword argument 'permit'"):
        _issue(route_context, permit=forged_permit)

    foreign_scanner = registered_zap_scanner(
        "sha256:" + "f" * 64,
        parser_contract_digest=(route_context.scanner_plan.scanner_contract.parser_contract_digest),
    )
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(route_context, scanner_registration=foreign_scanner)

    forged_release = route_context.capability_release.model_copy(
        update={"release_digest": "f" * 64}
    )
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(route_context, capability_release=forged_release)


def test_route_rejects_reset_receipt_for_a_different_valid_operation(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    mismatch = _with_fresh_journal(
        route_context,
        tmp_path / "reset-operation-mismatch" / "target-journal.sqlite3",
        reset_receipt_ordinal=2,
    )
    _, _, _, _, records = mismatch.target_journal.current_open_attempt(mismatch.target_attempt_id)

    assert records[0].record_type == "intent"
    assert records[0].operation.stage == "reset"
    assert records[0].operation.ordinal == 1
    assert records[1].record_type == "receipt"
    assert records[1].operation.stage == "reset"
    assert records[1].operation.ordinal == 2
    assert records[1].receipt is not None
    assert records[1].receipt.operation_id == records[1].operation.operation_id
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(mismatch)


def test_route_rejects_foreign_journal_coordinate_with_same_benchmark_id(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    authoritative = route_context.scanner_plan.manifest
    foreign_arm = authoritative.arms[0].model_copy(update={"arm_id": "arm:web-002-zap-foreign"})
    foreign_protocol = authoritative.protocol.model_copy(
        update={"seeds": [11], "repetitions_per_seed": 2}
    )
    foreign_manifest = BenchmarkManifest.model_validate(
        authoritative.model_copy(
            update={
                "campaign_digest": "0" * 64,
                "protocol": foreign_protocol,
                "arms": [foreign_arm],
            }
        ).model_dump(mode="json", by_alias=True)
    )
    foreign_coordinate = benchmark_target_coordinate(
        foreign_manifest,
        arm_id=foreign_arm.arm_id,
        seed=11,
        repetition=2,
    )
    foreign = _with_fresh_journal(
        replace(route_context, coordinate=foreign_coordinate),
        tmp_path / "foreign-coordinate" / "target-journal.sqlite3",
    )

    assert foreign_coordinate.benchmark_id == route_context.coordinate.benchmark_id
    assert foreign_coordinate.manifest_digest != route_context.coordinate.manifest_digest
    assert foreign_coordinate.arm != route_context.coordinate.arm
    assert foreign_coordinate.seed != route_context.coordinate.seed
    assert foreign_coordinate.repetition != route_context.coordinate.repetition
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(foreign)


def test_route_rejects_reset_and_isolation_environment_mismatch(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    mismatch = _with_fresh_journal(
        route_context,
        tmp_path / "environment-mismatch" / "target-journal.sqlite3",
        reset_environment_id="environment.foreign-reset",
    )
    records = mismatch.target_journal.current_open_attempt(mismatch.target_attempt_id)[4]

    assert records[1].receipt is not None
    assert records[3].receipt is not None
    assert records[1].receipt.environment_id != records[3].receipt.environment_id
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(mismatch)


def test_route_rejects_overlapping_reset_and_isolation_receipts(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    base = route_context.issued_at - timedelta(minutes=1)
    overlap = _with_fresh_journal(
        route_context,
        tmp_path / "receipt-overlap" / "target-journal.sqlite3",
        reset_completion_offset=timedelta(seconds=2),
        record_times=(
            base,
            base + timedelta(seconds=1),
            base + timedelta(seconds=4),
            base + timedelta(seconds=2),
            base + timedelta(seconds=3),
            base + timedelta(seconds=5),
        ),
    )
    records = overlap.target_journal.current_open_attempt(overlap.target_attempt_id)[4]

    assert records[1].receipt is not None
    assert records[3].receipt is not None
    assert records[1].receipt.completed_at > records[3].receipt.started_at
    assert records[1].receipt.completed_at <= records[1].occurred_at
    assert records[2].occurred_at <= records[3].receipt.started_at
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(overlap)


def test_route_rejects_nonmonotonic_journal_record_time(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    base = route_context.issued_at - timedelta(minutes=1)
    nonmonotonic = _with_fresh_journal(
        route_context,
        tmp_path / "nonmonotonic-records" / "target-journal.sqlite3",
        record_times=(
            base,
            base + timedelta(seconds=1),
            base + timedelta(seconds=3),
            base + timedelta(seconds=2),
            base + timedelta(seconds=4),
            base + timedelta(seconds=5),
        ),
    )
    records = nonmonotonic.target_journal.current_open_attempt(nonmonotonic.target_attempt_id)[4]

    assert records[1].occurred_at > records[2].occurred_at
    assert records[1].receipt is not None
    assert records[3].receipt is not None
    assert records[1].receipt.completed_at <= records[3].receipt.started_at
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(nonmonotonic)


def test_route_rejects_future_execution_intent(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    base = route_context.issued_at - timedelta(minutes=1)
    future = _with_fresh_journal(
        route_context,
        tmp_path / "future-execution" / "target-journal.sqlite3",
        record_times=(
            base,
            base + timedelta(seconds=1),
            base + timedelta(seconds=2),
            base + timedelta(seconds=3),
            base + timedelta(seconds=4),
            route_context.issued_at + timedelta(seconds=1),
        ),
    )
    records = future.target_journal.current_open_attempt(future.target_attempt_id)[4]

    assert all(
        previous.occurred_at <= current.occurred_at for previous, current in pairwise(records)
    )
    assert records[-1].record_type == "intent"
    assert records[-1].operation.stage == "execution"
    assert records[-1].occurred_at > route_context.issued_at
    with pytest.raises(WebProxyRouteAuthorityError, match="issuance failed closed"):
        _issue(future)


def test_route_invalidates_on_recovery_sequence_drift_and_cleanup(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    recovery = _with_fresh_journal(
        route_context,
        tmp_path / "recovery" / "target-journal.sqlite3",
    )
    recovery_bundle = _issue(recovery)
    recovery.target_journal.claim_recovery(recovery.attempt)
    with pytest.raises(WebProxyRouteAuthorityError, match="verification failed closed"):
        _verify(recovery, recovery_bundle)

    sequence = _with_fresh_journal(
        route_context,
        tmp_path / "sequence" / "target-journal.sqlite3",
    )
    sequence_bundle = _issue(sequence)
    sequence.target_journal.append_provider_error(sequence.execution_operation)
    with pytest.raises(WebProxyRouteAuthorityError, match="verification failed closed"):
        _verify(sequence, sequence_bundle)

    cleanup = _with_fresh_journal(
        route_context,
        tmp_path / "cleanup" / "target-journal.sqlite3",
    )
    cleanup_bundle = _issue(cleanup)
    execution_receipt = BenchmarkTargetStageReceipt(
        adapterDigest=cleanup.target_adapter.adapter_digest,
        coordinateDigest=cleanup.coordinate.coordinate_digest,
        stage="execution",
        operationId=cleanup.execution_operation.operation_id,
        environmentId=cleanup.isolation_evidence.environment_id,
        isolationId=cleanup.isolation_evidence.isolation_id,
        status="succeeded",
        startedAt=cleanup.issued_at,
        completedAt=cleanup.issued_at + timedelta(seconds=1),
        providerEvidenceDigest="d" * 64,
    )
    cleanup.target_journal.append_receipt(
        cleanup.execution_operation,
        execution_receipt,
    )
    cleanup_operation = _operation(cleanup.attempt, "cleanup", 1)
    cleanup_receipt = BenchmarkTargetStageReceipt(
        adapterDigest=cleanup.target_adapter.adapter_digest,
        coordinateDigest=cleanup.coordinate.coordinate_digest,
        stage="cleanup",
        operationId=cleanup_operation.operation_id,
        environmentId=cleanup.isolation_evidence.environment_id,
        isolationId=cleanup.isolation_evidence.isolation_id,
        status="succeeded",
        startedAt=cleanup.issued_at + timedelta(seconds=2),
        completedAt=cleanup.issued_at + timedelta(seconds=3),
        providerEvidenceDigest="e" * 64,
    )
    cleanup.target_journal.append_intent(cleanup_operation)
    cleanup.target_journal.append_receipt(cleanup_operation, cleanup_receipt)
    cleanup.target_journal.mark_completed(cleanup.target_attempt_id)
    with pytest.raises(WebProxyRouteAuthorityError, match="verification failed closed"):
        _verify(cleanup, cleanup_bundle)


def test_route_classifies_only_exact_cleanup_before_verification(
    route_context: RouteContext,
    tmp_path: Path,
) -> None:
    cleanup = _with_fresh_journal(
        route_context,
        tmp_path / "cleanup-before-verification" / "target-journal.sqlite3",
    )
    bundle = _issue(cleanup)
    cleanup_operation = _operation(cleanup.attempt, "cleanup", 1)
    cleanup_receipt = BenchmarkTargetStageReceipt(
        adapterDigest=cleanup.target_adapter.adapter_digest,
        coordinateDigest=cleanup.coordinate.coordinate_digest,
        stage="cleanup",
        operationId=cleanup_operation.operation_id,
        environmentId=cleanup.isolation_evidence.environment_id,
        isolationId=cleanup.isolation_evidence.isolation_id,
        status="succeeded",
        startedAt=cleanup.issued_at + timedelta(seconds=5),
        completedAt=cleanup.issued_at + timedelta(seconds=6),
        providerEvidenceDigest="e" * 64,
    )
    journal_clock = _journal_clock(
        (
            cleanup.issued_at + timedelta(seconds=5),
            cleanup.issued_at + timedelta(seconds=7),
        )
    )
    with patch.object(target_recovery_module, "datetime", journal_clock):
        cleanup.target_journal.append_intent(cleanup_operation)
        cleanup.target_journal.append_receipt(cleanup_operation, cleanup_receipt)
    cleanup.target_journal.mark_completed(cleanup.target_attempt_id)

    with pytest.raises(
        WebProxyRouteTargetCleanupInvalidated,
        match="invalidated by completed Target cleanup",
    ):
        _verify(cleanup, bundle)

    foreign_request = cleanup.request.model_copy(update={"agent_id": "agent.foreign"})
    with pytest.raises(WebProxyRouteAuthorityError) as caught:
        _verify(cleanup, bundle, request=foreign_request)
    assert not isinstance(caught.value, WebProxyRouteTargetCleanupInvalidated)

    newer_attempt = cleanup.target_journal.begin_attempt(
        cleanup.target_adapter,
        cleanup.coordinate,
    )
    assert newer_attempt.fence > cleanup.attempt.fence
    assert (
        cleanup.target_journal.latest_scope_fence(
            adapter_digest=cleanup.target_adapter.adapter_digest,
            coordinate_digest=cleanup.coordinate.coordinate_digest,
        )
        == newer_attempt.fence
    )
    with pytest.raises(WebProxyRouteAuthorityError) as stale:
        _verify(cleanup, bundle)
    assert not isinstance(stale.value, WebProxyRouteTargetCleanupInvalidated)

    _verify_cleanup_history(cleanup, bundle)
    with pytest.raises(WebProxyRouteAuthorityError, match="historical"):
        _verify_cleanup_history(cleanup, bundle, request=foreign_request)

    signature = bundle.route.signature_base64url
    substituted_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    forged_bundle = WebProxyRouteBundle(
        route=SignedWebProxyRoute(
            keyId=bundle.route.key_id,
            statement=bundle.route.statement,
            signatureBase64url=substituted_signature,
        )
    )
    with pytest.raises(WebProxyRouteAuthorityError, match="historical"):
        _verify_cleanup_history(cleanup, forged_bundle)


@pytest.mark.parametrize(
    ("policy_value", "target_value"),
    (("3", "1"), (3.0, 1.0), (True, True)),
)
def test_route_wire_is_proxy_only_public_safe_and_rejects_numeric_coercion(
    route_context: RouteContext,
    policy_value: object,
    target_value: object,
) -> None:
    bundle = _issue(route_context)
    statement = bundle.route.statement
    policy = statement.runtime_policy
    public = json.dumps(bundle.model_dump(mode="json", by_alias=True), sort_keys=True)

    assert policy.worker_network_mode == NetworkMode.EGRESS_PROXY.value
    assert policy.proxy_alias == "egress-proxy"
    assert policy.target_service_alias == "target"
    assert policy.target_scheme == "http"
    assert policy.target_port == 8080
    assert policy.target_path == "/v1/users/lookup"
    assert policy.allowed_method == "GET"
    assert policy.request_budget == 3
    assert policy.max_response_bytes_per_request == 32768
    assert policy.caller_authored_payload_allowed is False
    assert policy.connect_allowed is False
    assert policy.dns_allowed is False
    assert policy.direct_worker_target_network_attachment_allowed is False
    assert policy.host_port_publication_allowed is False
    assert statement.proxy_only_bridge_required is True
    assert statement.target.target_network_internal is True
    assert statement.target.published_port_count == 0
    assert statement.target.target_network_container_count == 1
    assert "privateKey" not in public
    assert "dockerSocket" not in public
    assert "targetNetworkName" not in public
    assert "externalNetworkRoutes" not in public
    assert "requestBody" not in public

    raw_policy = policy.model_dump(mode="json", by_alias=True)
    raw_policy["requestBudget"] = policy_value
    with pytest.raises(ValidationError):
        WebProxyRouteRuntimePolicy.model_validate(raw_policy)

    raw_target = statement.target.model_dump(mode="json", by_alias=True)
    raw_target["activeFence"] = target_value
    with pytest.raises(ValidationError):
        WebProxyRouteTargetBinding.model_validate(raw_target)

    raw_statement = statement.model_dump(mode="json", by_alias=True)
    raw_statement["workerAttached"] = 0
    with pytest.raises(ValidationError):
        WebProxyRouteStatement.model_validate(raw_statement)

    raw_verification = _verify(
        route_context,
        bundle,
    ).model_dump(mode="json", by_alias=True)
    raw_verification["executionAuthorized"] = 0
    with pytest.raises(ValidationError):
        WebProxyRouteVerification.model_validate(raw_verification)
