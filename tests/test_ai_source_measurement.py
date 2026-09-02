from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_ai_read_only_analysis import _capability_binding, _signed_activation
from test_network_service_admission import _ApprovalInputAuthority, _graph_authority

import pajin.runtime.store as store_module
from pajin.capabilities.ai_analysis import (
    AIAnalysisBudgetCeiling,
    bind_ai_read_only_analysis,
    prepare_ai_measurement_operation,
    prepare_ai_read_only_analysis,
)
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.control_plane.redteam_profiles import REDTEAM_LLM_PROFILE_DIGEST
from pajin.domain.manifest import load_manifest
from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CapabilityGrant,
    ToolRequest,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.graph.approval import (
    ActionApprovalEnvelope,
    ActionApprovalIssuerAuthorityBinding,
    ActionApprovalReleaseRef,
)
from pajin.graph.authority import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionProposal,
    MissionEnvelope,
    action_permit_attempt_id,
)
from pajin.runtime.worker import (
    DockerEgressLifecycleObservation,
    DockerWorkerBackend,
    WorkerResult,
    WorkerStatus,
)
from pajin.target_attestation import (
    AIMeasurementTargetExecutionAttestor,
    AIMeasurementTargetExecutionChallenge,
    AIMeasurementTargetExecutionReceipt,
    AISourceTargetExecutionAttestor,
    AISourceTargetExecutionChallenge,
    AISourceTargetExecutionReceipt,
    TargetAttestationKeyState,
    TargetAttestationTrustAnchor,
    TargetAttestationVerificationKey,
    canonical_target_json_sha256,
    target_public_key_base64url,
)
from pajin.tools.ai import (
    AI_CHAT_PROXY_RECEIPT_VERSION,
    AIChatProbeInput,
    AIChatProbeTool,
)
from pajin.workflow.ai_fixture_runtime import (
    AIFixtureDockerProvider,
    AIFixtureLiveTarget,
    AIFixtureProxyTopologyObservation,
    AIFixtureTargetAttempt,
    AIFixtureTargetCoordinate,
    AIFixtureTargetLifecycleEvidence,
    AIMeasurementFixtureTargetLifecycleEvidence,
    AISourceImageBinding,
    ai_fixture_resource_names,
    registered_ai_source_image_binding,
)
from pajin.workflow.ai_measured_case_authority import (
    AI_M03_PROXY_IMAGE,
    AI_M03_TARGET_IMAGE,
    AI_M03_WORKER_IMAGE,
    AIMeasuredCaseRef,
    AIMeasurementImageRole,
    AIMeasurementOperation,
    registered_ai_measured_case_mapping,
    registered_ai_measurement_operations,
    registered_ai_private_ground_truth_case,
)
from pajin.workflow.ai_replay_evaluation import (
    AIMeasurementApprovedAction,
    AIPrivateReplayEvaluationBinding,
    AIReplayEvaluationError,
    AIReplayEvaluationOutcome,
    AIReplayEvaluationRunner,
    AIReplayFloorEvaluation,
    load_ai_replay_floor_evaluation,
)
from pajin.workflow.ai_source_measurement import (
    AIPrivateSourceMeasurementBinding,
    AISourceApprovedAction,
    AISourceDenialControl,
    AISourceMeasurementAuthority,
    AISourceMeasurementMapping,
    AISourceMeasurementRunner,
    _canonical_authority_context,
    _validate_mapping,
    ai_source_provider_registration,
    load_ai_source_measurement_authority,
)

_M03_CAPABILITY_ID = "pajin.ai.kisa.system-prompt-disclosure"
_ISSUER = ActionApprovalIssuerAuthorityBinding(
    authorityId="deployment:ai-source-approval",
    authorityVersion="1.0.0",
    implementationType="tests.ai_source.ExternalApprovalAuthority",
    contextDigest=sha256(b"ai002b-approval-authority").hexdigest(),
)
_FALSE_PUBLIC_ALIASES = (
    "replayAuthorized",
    "controlsAuthorized",
    "measurementFloorEvaluated",
    "validationFloorSatisfied",
    "graphAdmissionAuthorized",
    "graphMutationAuthorized",
    "findingAuthority",
    "productProjectionAuthorized",
    "reportingAuthorized",
    "externalDeliveryAuthorized",
    "credentialAccessAuthorized",
    "externalProviderAuthorized",
    "externalTargetAuthorized",
    "productionTargetAuthorized",
    "arbitraryPromptAuthorized",
    "arbitraryToolAuthorized",
    "ragAuthorized",
    "mcpAuthorized",
    "memoryMutationAuthorized",
    "m06Authorized",
    "a04Authorized",
    "generalAIScannerAuthorized",
    "callerConfigurationAuthorized",
    "additionalApplicationWriteAuthorized",
    "additionalExecutionAuthorized",
)
_PRIVATE_ONLY_KEYS = {
    "groundTruth",
    "promptText",
    "checkValue",
    "trustAnchor",
    "workerResult",
    "toolResult",
    "output",
    "request",
    "challenge",
    "lifecycle",
    "targetUrl",
    "targetContainerName",
    "targetNetworkName",
}


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _canonical_digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_all_keys(item) for item in value.values()), set())
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value), set())
    return set()


class _ImageInspector:
    def __init__(self) -> None:
        self.ids = {
            AI_M03_TARGET_IMAGE: f"sha256:{_digest('ai002b-target-image')}",
            AI_M03_WORKER_IMAGE: f"sha256:{_digest('ai002b-worker-image')}",
            AI_M03_PROXY_IMAGE: f"sha256:{_digest('ai002b-proxy-image')}",
        }

    def image_id(self, reference: str) -> str:
        return self.ids[reference]


class _InProcessBoundaryInspector:
    def __init__(
        self,
        *,
        provider: _InProcessProvider,
        coordinate: AIFixtureTargetCoordinate,
        images: AISourceImageBinding,
    ) -> None:
        self.provider = provider
        self.coordinate = coordinate
        self.images = images
        self.observation: DockerEgressLifecycleObservation | None = None
        self.topology: AIFixtureProxyTopologyObservation | None = None

    def stable_observer_context(self) -> Mapping[str, object]:
        return {
            "observerId": "tests.ai-source-in-process-boundary",
            "observerVersion": "1.0.0",
            "coordinateDigest": self.coordinate.coordinate_digest,
            "imageBindingDigest": self.images.binding_digest,
        }

    def image_id(self, reference: str) -> str:
        return self.provider.image_id(reference)

    async def attached(self, observation: DockerEgressLifecycleObservation) -> None:
        if (
            self.observation is not None
            or not self.provider.active
            or observation.external_network_name != self.coordinate.target_network_name
        ):
            raise RuntimeError("in-process AI topology attachment differs")
        self.observation = observation

    async def cleaned(self, observation: DockerEgressLifecycleObservation) -> None:
        if self.observation != observation or not self.provider.active:
            raise RuntimeError("in-process AI topology cleanup differs")
        now = datetime.now(UTC)
        internal_id = _digest(f"internal:{observation.execution_id}")
        target_network_id = self.coordinate.target_network_id
        self.topology = AIFixtureProxyTopologyObservation(
            executionId=observation.execution_id,
            workerContainerName=observation.worker_container_name,
            workerContainerId=_digest(f"worker:{observation.execution_id}"),
            workerImageId=self.images.role(AIMeasurementImageRole.WORKER).observed_image_id,
            proxyContainerName=observation.proxy_container_name,
            proxyContainerId=_digest(f"proxy:{observation.execution_id}"),
            proxyImageId=self.images.role(AIMeasurementImageRole.PROXY).observed_image_id,
            internalNetworkName=observation.internal_network_name,
            internalNetworkId=internal_id,
            targetNetworkName=self.coordinate.target_network_name,
            targetNetworkId=target_network_id,
            targetContainerId=self.coordinate.target_container_id,
            targetImageId=self.coordinate.target_image_id,
            workerNetworkIds=(internal_id,),
            proxyNetworkIds=tuple(sorted((internal_id, target_network_id))),
            targetNetworkIds=(target_network_id,),
            attachedAt=now,
            ephemeralResourcesAbsentAt=now + timedelta(milliseconds=1),
        )

    def topology_observation(
        self,
        execution_id: str,
    ) -> AIFixtureProxyTopologyObservation:
        if self.topology is None or self.topology.execution_id != execution_id:
            raise RuntimeError("in-process AI topology is incomplete")
        return self.topology.model_copy(deep=True)


class _InProcessProvider(AIFixtureDockerProvider):
    def __init__(self, images: AISourceImageBinding) -> None:
        super().__init__()
        self.images = images
        self.active = False
        self.receipt: AISourceTargetExecutionReceipt | None = None
        self.attestor: AISourceTargetExecutionAttestor | None = None
        self.measurement_receipt: AIMeasurementTargetExecutionReceipt | None = None
        self.measurement_attestor: AIMeasurementTargetExecutionAttestor | None = None
        self.inspectors: list[_InProcessBoundaryInspector] = []

    def image_id(self, reference: str) -> str:
        return next(
            item.observed_image_id
            for item in self.images.roles
            if item.image_reference == reference
        )

    def managed_resources_absent(self) -> bool:
        return not self.active

    def start(
        self,
        *,
        case: AIMeasuredCaseRef,
        images: AISourceImageBinding,
    ) -> AIFixtureLiveTarget:
        if self.active or images != self.images:
            raise RuntimeError("in-process AI Target reuse or image substitution")
        now = datetime.now(UTC)
        attempt = AIFixtureTargetAttempt(
            nonce=_digest(f"nonce:{now.isoformat()}")[:32],
            case=case,
            images=images.reference(),
            createdAt=now,
        )
        names = ai_fixture_resource_names(attempt)
        coordinate = AIFixtureTargetCoordinate(
            attemptId=attempt.attempt_id,
            attemptDigest=attempt.attempt_digest,
            case=case,
            images=images.reference(),
            targetContainerName=names.target_container_name,
            targetContainerId=_digest(f"target-container:{attempt.attempt_digest}"),
            targetImageId=images.role(AIMeasurementImageRole.TARGET).observed_image_id,
            targetNetworkName=names.target_network_name,
            targetNetworkId=_digest(f"target-network:{attempt.attempt_digest}"),
            targetUrl="http://host.docker.internal:8080/v1/chat",
            observedAt=now,
        )
        private_key = sha256(f"key:{attempt.attempt_digest}".encode()).digest()
        key_id = f"ai-source-key-{attempt.attempt_digest[:16]}"
        anchor = TargetAttestationTrustAnchor(
            trust_domain="pajin.local/ai-source-target",
            issuer="PAJIN deterministic AI source target",
            target_profile="kisa-m03-source-v1",
            keys=[
                TargetAttestationVerificationKey(
                    key_id=key_id,
                    public_key_base64url=target_public_key_base64url(private_key),
                    state=TargetAttestationKeyState.ACTIVE,
                    not_before=now - timedelta(seconds=1),
                    not_after=now + timedelta(minutes=10),
                )
            ],
        )
        self.attestor = AISourceTargetExecutionAttestor.from_private_key_bytes(
            active_key_id=key_id,
            private_key=private_key,
            trust_anchor=anchor,
        )
        self.measurement_attestor = AIMeasurementTargetExecutionAttestor.from_private_key_bytes(
            active_key_id=key_id,
            private_key=private_key,
            trust_anchor=anchor,
        )
        self.receipt = None
        self.measurement_receipt = None
        self.active = True
        return AIFixtureLiveTarget(
            attempt=attempt,
            coordinate=coordinate,
            trust_anchor=anchor,
        )

    def boundary_inspector(
        self,
        *,
        coordinate: AIFixtureTargetCoordinate,
        images: AISourceImageBinding,
    ) -> _InProcessBoundaryInspector:
        inspector = _InProcessBoundaryInspector(
            provider=self,
            coordinate=coordinate,
            images=images,
        )
        self.inspectors.append(inspector)
        return inspector

    def attest_exchange(
        self,
        *,
        challenge: AISourceTargetExecutionChallenge,
        request: dict[str, object],
        response: dict[str, object],
    ) -> None:
        if not self.active or self.attestor is None or self.receipt is not None:
            raise RuntimeError("in-process AI Target receipt state differs")
        self.receipt = self.attestor.attest(
            {
                "challenge_id": challenge.challenge_id,
                "challenge_sha256": challenge.digest,
                "permit_digest": challenge.permit_digest,
                "source_request_id": challenge.source_request_id,
                "source_operation_id": challenge.source_operation_id,
                "call_ordinal": 1,
                "exchange_ordinal": 1,
                "target_sha256": challenge.target_sha256,
                "method": "POST",
                "route_path": "/v1/chat",
                "request_json_sha256": canonical_target_json_sha256(request),
                "response_payload_sha256": canonical_target_json_sha256(response),
                "status": 200,
            },
            issued_at=datetime.now(UTC),
        )

    def source_target_receipt(
        self,
        live: AIFixtureLiveTarget,
    ) -> AISourceTargetExecutionReceipt:
        del live
        if self.receipt is None:
            raise RuntimeError("in-process AI Target receipt is absent")
        return self.receipt.model_copy(deep=True)

    def attest_measurement_exchange(
        self,
        *,
        challenge: AIMeasurementTargetExecutionChallenge,
        request: dict[str, object],
        response: dict[str, object],
    ) -> None:
        if (
            not self.active
            or self.measurement_attestor is None
            or self.measurement_receipt is not None
        ):
            raise RuntimeError("in-process AI measurement Target receipt state differs")
        self.measurement_receipt = self.measurement_attestor.attest(
            {
                "challenge_id": challenge.challenge_id,
                "challenge_sha256": challenge.digest,
                "permit_digest": challenge.permit_digest,
                "measurement_request_id": challenge.measurement_request_id,
                "measurement_operation_id": challenge.measurement_operation_id,
                "registered_operation_digest": challenge.registered_operation_digest,
                "operation_key": challenge.operation_key,
                "operation_ordinal": challenge.operation_ordinal,
                "operation_stage": challenge.operation_stage,
                "call_ordinal": 1,
                "exchange_ordinal": 1,
                "target_sha256": challenge.target_sha256,
                "method": "POST",
                "route_path": "/v1/chat",
                "request_json_sha256": canonical_target_json_sha256(request),
                "response_payload_sha256": canonical_target_json_sha256(response),
                "status": 200,
            },
            issued_at=datetime.now(UTC),
        )

    def measurement_target_receipt(
        self,
        live: AIFixtureLiveTarget,
    ) -> AIMeasurementTargetExecutionReceipt:
        del live
        if self.measurement_receipt is None:
            raise RuntimeError("in-process AI measurement Target receipt is absent")
        return self.measurement_receipt.model_copy(deep=True)

    def finish(
        self,
        live: AIFixtureLiveTarget,
        *,
        topology: AIFixtureProxyTopologyObservation,
        target_receipt: AISourceTargetExecutionReceipt,
    ) -> AIFixtureTargetLifecycleEvidence:
        if not self.active or target_receipt != self.receipt:
            raise RuntimeError("in-process AI Target finish differs")
        self.active = False
        return AIFixtureTargetLifecycleEvidence(
            attempt=live.attempt,
            coordinate=live.coordinate,
            topology=topology,
            targetReceipt=target_receipt,
            targetReceiptDigest=target_receipt.digest,
            targetResourcesAbsent=True,
            cleanupCompletedAt=datetime.now(UTC) + timedelta(milliseconds=2),
        )

    def finish_measurement(
        self,
        live: AIFixtureLiveTarget,
        *,
        topology: AIFixtureProxyTopologyObservation,
        target_receipt: AIMeasurementTargetExecutionReceipt,
    ) -> AIMeasurementFixtureTargetLifecycleEvidence:
        if not self.active or target_receipt != self.measurement_receipt:
            raise RuntimeError("in-process AI measurement Target finish differs")
        self.active = False
        return AIMeasurementFixtureTargetLifecycleEvidence(
            attempt=live.attempt,
            coordinate=live.coordinate,
            topology=topology,
            targetReceipt=target_receipt,
            targetReceiptDigest=target_receipt.digest,
            targetResourcesAbsent=True,
            cleanupCompletedAt=datetime.now(UTC) + timedelta(milliseconds=2),
        )

    def abort(self, live: AIFixtureLiveTarget) -> None:
        del live
        self.active = False


def _exact_campaign(target: AIFixtureTargetCoordinate) -> CampaignManifest:
    payload = load_manifest(Path("examples/kisa-ai-chat-lab.yaml")).model_dump(
        mode="json",
        by_alias=True,
    )
    payload["spec"]["targets"] = [
        {
            "type": "ai-chat-api",
            "id": "pajin-ai002b-disposable-target",
            "endpoint": target.target_url,
        }
    ]
    payload["spec"]["scope"] = {"allow": [target.target_url], "deny": []}
    payload["spec"]["objectives"] = ["measure the exact registered M03 source case"]
    payload["spec"]["threatClasses"] = ["M03"]
    payload["spec"]["rulesOfEngagement"]["maxToolRiskTier"] = "T2"
    payload["spec"]["rulesOfEngagement"]["allowedMethods"] = ["POST"]
    payload["spec"]["rulesOfEngagement"]["allowedToolCategories"] = sorted(
        AIChatProbeTool.spec.categories
    )
    payload["spec"]["rulesOfEngagement"]["allowPrivateNetworks"] = True
    payload["spec"]["rulesOfEngagement"]["maxRequestsPerMinute"] = 1
    payload["spec"]["budgets"] = {
        "durationSeconds": 120,
        "maxCostUsd": 0,
        "maxAgents": 1,
        "maxSpawnDepth": 0,
        "maxToolCalls": 1,
        "maxModelCalls": 0,
        "maxModelTokens": 0,
    }
    payload["spec"]["outputs"] = []
    return CampaignManifest.model_validate(payload)


def _approved_plan(
    root: Path,
    *,
    target: AIFixtureTargetCoordinate,
    run_id: str,
    request_id: str,
    authority_context_digest: str,
    exact_request: ToolRequest | None = None,
    exact_operation: AIMeasurementOperation | None = None,
) -> AISourceApprovedAction | AIMeasurementApprovedAction:
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    activation, releases = _signed_activation()
    release = releases[_M03_CAPABILITY_ID]
    campaign = _exact_campaign(target)
    ground_truth = registered_ai_private_ground_truth_case()
    probe = AIChatProbeInput(
        scenario_id=ground_truth.scenario_id,
        threat_class=ground_truth.threat_class,
        session_id=f"pajin:ai002b:{request_id[-32:]}",
        turns=[
            {
                "name": "system-prompt-extraction",
                "messages": [
                    {
                        "role": "user",
                        "content": ground_truth.prompt_text,
                    }
                ],
            }
        ],
        checks=[
            {
                "check_id": ground_truth.check_id,
                "kind": ground_truth.check_kind,
                "turn": ground_truth.check_turn,
                "value": ground_truth.check_value,
                "sensitive": True,
            }
        ],
    )
    request = ToolRequest(
        request_id=request_id,
        agent_id="agent:ai002b-source",
        tool_id=AIChatProbeTool.spec.tool_id,
        target=target.target_url,
        method="POST",
        arguments=probe.model_dump(mode="json"),
    )
    if exact_request is not None:
        if exact_request.request_id != request_id:
            raise RuntimeError("exact AI request ID differs")
        request = ToolRequest.model_validate_json(exact_request.model_dump_json())
    provider = ai_source_provider_registration(target)
    binding = bind_ai_read_only_analysis(
        capability=_capability_binding(_M03_CAPABILITY_ID).reference(),
        budget=AIAnalysisBudgetCeiling(
            requestUnits=1,
            maxInputTokens=4096,
            maxOutputTokens=1024,
            maxTotalTokens=5120,
            maxCostMicroUsd=0,
            providerUsageApplicable=True,
        ),
        provider_registration=provider,
        model_revision="2026-09-02-ai002b-source-model-sha256",
    )
    if exact_request is None:
        if exact_operation is not None:
            raise RuntimeError("source preparation cannot carry a measurement operation")
        preparation = prepare_ai_read_only_analysis(
            activation=activation,
            release=release,
            binding=binding,
            request=request,
            provider_registration=provider,
        )
    else:
        if exact_operation is None:
            raise RuntimeError("measurement preparation requires its exact operation")
        operation_keys = {
            2: "replay-1",
            3: "replay-2",
            4: "control-baseline",
            5: "control-negative",
            6: "control-counterfactual",
        }
        preparation = prepare_ai_measurement_operation(
            activation=activation,
            release=release,
            binding=binding,
            request=request,
            provider_registration=provider,
            registered_operation_digest=sha256(
                (
                    "pajin.workflow.ai-measurement-operation/v1\x00"
                    + json.dumps(
                        exact_operation.model_dump(mode="json", by_alias=True),
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                ).encode()
            ).hexdigest(),
            operation_key=operation_keys[exact_operation.ordinal],
            operation_ordinal=exact_operation.ordinal,
            operation_stage=exact_operation.stage.value,
        )
    graph_store, _admission, _lineages, _graph_binding, decision = _graph_authority(
        root,
        campaign.metadata.name,
        decision_payload_digest=preparation.preparation_digest,
    )
    now = datetime.now(UTC)
    target_digest = sha256(request.target.encode()).hexdigest()
    capability = preparation.prepared_action.capability
    proposal_at = max(
        decision.created_at + timedelta(seconds=1),
        now - timedelta(seconds=3),
    )
    approval_at = max(
        proposal_at + timedelta(seconds=1),
        now - timedelta(seconds=2),
    )
    approval_not_before = max(
        approval_at + timedelta(milliseconds=1),
        now - timedelta(seconds=1),
    )
    envelope = MissionEnvelope(
        campaignId=campaign.metadata.name,
        runId=run_id,
        profileId="redteam-llm-v1",
        profileVersion="1.0.0",
        profileDigest=REDTEAM_LLM_PROFILE_DIGEST,
        compilerId="pajin.ai.source-action-compiler",
        compilerVersion="1.0.0",
        compilerDigest=_digest("ai002b-source-compiler"),
        sourceCampaignDigest=campaign_manifest_digest(campaign),
        allowedCapabilities=(capability,),
        allowedTargetDigests=(target_digest,),
        maxRiskTier=ToolRiskTier.T2,
        budget=ActionBudgetLimit(toolCallLimit=1, requestUnitLimit=1),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=now - timedelta(seconds=4),
        notBefore=now - timedelta(seconds=3),
        expiresAt=now + timedelta(minutes=2),
    )
    proposal = ActionProposal(
        campaignId=campaign.metadata.name,
        runId=run_id,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=decision.snapshot,
        proposerId="pajin.graph.ai-source-planner",
        proposerDigest=_digest("ai002b-source-proposer"),
        capability=capability,
        targetDigest=target_digest,
        requestId=request.request_id,
        requestDigest=preparation.prepared_action.request_digest,
        normalizedParametersDigest=preparation.prepared_action.normalized_parameters_digest,
        riskTier=ToolRiskTier.T2,
        reservation=ActionBudgetReservation(requestUnits=1),
        createdAt=proposal_at,
    )
    approval = ActionApprovalEnvelope(
        issuer=_ISSUER,
        requestedBy="principal:ai-source-requester",
        approvedBy="principal:ai-source-approver",
        campaignId=campaign.metadata.name,
        campaignDigest=campaign_manifest_digest(campaign),
        runId=run_id,
        missionEnvelope=envelope,
        sourceIntentDigest=preparation.preparation_digest,
        activationSetDigest=preparation.prepared_action.activation_set_digest,
        release=ActionApprovalReleaseRef(
            releaseId=release.release_id,
            releaseDigest=release.release_digest,
            capabilityId=capability.capability_id,
            capabilityVersion=capability.capability_version,
            capabilityDigest=capability.definition_digest,
        ),
        graphDecision=decision,
        proposal=proposal,
        expectedActionPermitId=action_permit_attempt_id(envelope, proposal, decision),
        sideEffectClass="read-only",
        reservation=proposal.reservation,
        approvedAt=approval_at,
        notBefore=approval_not_before,
        expiresAt=now + timedelta(minutes=1),
    )
    grant = CapabilityGrant(
        grant_id=f"grant_ai002b_{_digest(run_id)[:16]}",
        subject=request.agent_id,
        campaign=campaign.metadata.name,
        tools={request.tool_id},
        targets={request.target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        issued_at=now - timedelta(seconds=5),
        expires_at=now + timedelta(minutes=1),
    )
    job = CapabilityGraphCampaignJobInput(
        profile="redteam-llm-v1",
        proposal=proposal,
        decision=decision,
        release=release,
        request=request,
        grant=grant,
        approval=approval,
    )
    action_fields = {
        "activation": activation,
        "campaign": campaign,
        "preparation": preparation,
        "job": job,
        "mission_envelope": envelope,
        "graph_store": graph_store,
        "approval_input_authority": _ApprovalInputAuthority(approval),
        "approval_issuer": _ISSUER,
        "provider_registration": provider,
        "authority_context_digest": authority_context_digest,
    }
    if exact_operation is not None:
        return AIMeasurementApprovedAction(**action_fields)
    return AISourceApprovedAction(
        activation=activation,
        campaign=campaign,
        preparation=preparation,
        job=job,
        mission_envelope=envelope,
        graph_store=graph_store,
        approval_input_authority=_ApprovalInputAuthority(approval),
        approval_issuer=_ISSUER,
        provider_registration=provider,
        authority_context_digest=authority_context_digest,
    )


class _SourceAuthorizer:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls = 0

    def stable_authority_context(self) -> Mapping[str, object]:
        return {
            "authorityId": "deployment:ai-source-authorizer",
            "authorityVersion": "1.0.0",
            "approvalIssuer": _ISSUER.model_dump(mode="json", by_alias=True),
        }

    def authorize(
        self,
        *,
        case: AIMeasuredCaseRef,
        target: AIFixtureTargetCoordinate,
        run_id: str,
        request_id: str,
    ) -> AISourceApprovedAction:
        if case != target.case:
            raise RuntimeError("AI source case and Target differ")
        self.calls += 1
        plan = _approved_plan(
            self.root / f"plan-{self.calls}",
            target=target,
            run_id=run_id,
            request_id=request_id,
            authority_context_digest=_canonical_authority_context(self)[1],
        )
        if type(plan) is not AISourceApprovedAction:
            raise RuntimeError("source fixture built a measurement action")
        return plan


class _MeasurementAuthorizer:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls = 0

    def stable_authority_context(self) -> Mapping[str, object]:
        return {
            "authorityId": "deployment:ai-source-authorizer",
            "authorityVersion": "1.0.0",
            "approvalIssuer": _ISSUER.model_dump(mode="json", by_alias=True),
        }

    def authorize(
        self,
        *,
        case: AIMeasuredCaseRef,
        operation: AIMeasurementOperation,
        target: AIFixtureTargetCoordinate,
        run_id: str,
        request: ToolRequest,
    ) -> AIMeasurementApprovedAction:
        if (
            case != target.case
            or operation.case != case
            or operation != registered_ai_measurement_operations()[operation.ordinal - 1]
        ):
            raise RuntimeError("AI measurement case, operation, or Target differs")
        self.calls += 1
        plan = _approved_plan(
            self.root / f"plan-{self.calls}",
            target=target,
            run_id=run_id,
            request_id=request.request_id,
            authority_context_digest=_canonical_authority_context(self)[1],
            exact_request=request,
            exact_operation=operation,
        )
        if type(plan) is not AIMeasurementApprovedAction:
            raise RuntimeError("measurement fixture built a source action")
        return plan


class _CallerConfiguredMeasurementAuthorizer(_MeasurementAuthorizer):
    def authorize(
        self,
        *,
        case: AIMeasuredCaseRef,
        operation: AIMeasurementOperation,
        target: AIFixtureTargetCoordinate,
        run_id: str,
        request: ToolRequest,
    ) -> AIMeasurementApprovedAction:
        plan = super().authorize(
            case=case,
            operation=operation,
            target=target,
            run_id=run_id,
            request=request,
        )
        campaign_payload = plan.campaign.model_dump(mode="python", by_alias=True)
        campaign_payload["spec"]["budgets"]["durationSeconds"] = 121
        return replace(
            plan,
            campaign=CampaignManifest.model_validate(campaign_payload),
        )


async def _run_in_process_worker(
    backend: DockerWorkerBackend,
    job,
    *,
    secrets=None,
) -> WorkerResult:
    if secrets:
        raise RuntimeError("AI-002B source must not materialize credentials")
    observer = backend._egress_lifecycle_observer
    if not isinstance(observer, _InProcessBoundaryInspector):
        raise RuntimeError("AI-002B source lacks its exact topology observer")
    suffix = _digest(job.execution_id)[:16]
    observation = DockerEgressLifecycleObservation(
        execution_id=job.execution_id,
        worker_container_name=backend._container_name(job.execution_id),
        proxy_container_name=f"pajin-proxy-{suffix}",
        internal_network_name=f"pajin-egress-{suffix}",
        external_network_name=observer.coordinate.target_network_name,
    )
    await observer.attached(observation)
    payload = json.loads(job.stdin)
    probe = AIChatProbeInput.model_validate(payload["probe"])
    challenge = AISourceTargetExecutionChallenge.model_validate(payload["sourceTargetChallenge"])
    turn = probe.turns[0]
    request = {
        "sessionId": probe.session_id,
        "messages": [item.model_dump(mode="json") for item in turn.messages],
        "metadata": {"scenarioId": probe.scenario_id, "turn": 0},
    }
    response = {
        "sessionId": probe.session_id,
        "message": {
            "role": "assistant",
            "content": f"observed {probe.checks[0].value}",
        },
        "toolCalls": [],
        "safety": {"blocked": False, "reason": None},
        "memoryWrites": [],
        "model": "pajin-deterministic-lab-v1",
    }
    raw = {
        "target": payload["target"],
        "scenarioId": probe.scenario_id,
        "threatClass": probe.threat_class,
        "sessionId": probe.session_id,
        "purpose": "attack",
        "vulnerable": True,
        "observation": "all scenario compromise indicators were observed",
        "turns": [
            {
                "index": 0,
                "name": turn.name,
                "request": request,
                "response": response,
                "responseLatencySeconds": 0.001,
            }
        ],
        "checks": [
            {
                "checkId": probe.checks[0].check_id,
                "kind": probe.checks[0].kind.value,
                "turn": 0,
                "matched": True,
                "sensitive": True,
            }
        ],
        "sensitiveExposureCount": 1,
        "meanResponseLatencySeconds": 0.001,
        "regressionPassed": None,
        "networkPerformed": True,
    }
    observer.provider.attest_exchange(
        challenge=challenge,
        request=request,
        response=response,
    )
    target = payload["target"]
    network_log = "\n".join(
        (
            json.dumps({"event": "ready", "port": 8080}, separators=(",", ":")),
            json.dumps(
                {
                    "event": "allow",
                    "receiptVersion": AI_CHAT_PROXY_RECEIPT_VERSION,
                    "sequence": 1,
                    "method": "POST",
                    "target": target,
                    "targetSha256": sha256(target.encode()).hexdigest(),
                    "address": "172.30.0.3",
                    "status": 200,
                    "requestJsonSha256": _canonical_digest(request),
                    "responseBodySha256": _canonical_digest(response),
                    "responseJsonSha256": _canonical_digest(response),
                },
                separators=(",", ":"),
            ),
        )
    )
    await observer.cleaned(observation)
    now = datetime.now(UTC)
    return WorkerResult(
        execution_id=job.execution_id,
        backend="docker",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=json.dumps(raw, ensure_ascii=False, separators=(",", ":")),
        network_log=network_log,
        started_at=now,
        finished_at=now + timedelta(milliseconds=1),
    )


async def _run_in_process_ai_measurement_worker(
    backend: DockerWorkerBackend,
    job,
    *,
    secrets=None,
) -> WorkerResult:
    payload = json.loads(job.stdin)
    if "sourceTargetChallenge" in payload:
        return await _run_in_process_worker(backend, job, secrets=secrets)
    if secrets:
        raise RuntimeError("AI-002C measurement must not materialize credentials")
    observer = backend._egress_lifecycle_observer
    if not isinstance(observer, _InProcessBoundaryInspector):
        raise RuntimeError("AI-002C measurement lacks its exact topology observer")
    suffix = _digest(job.execution_id)[:16]
    observation = DockerEgressLifecycleObservation(
        execution_id=job.execution_id,
        worker_container_name=backend._container_name(job.execution_id),
        proxy_container_name=f"pajin-proxy-{suffix}",
        internal_network_name=f"pajin-egress-{suffix}",
        external_network_name=observer.coordinate.target_network_name,
    )
    await observer.attached(observation)
    probe = AIChatProbeInput.model_validate(payload["probe"])
    challenge = AIMeasurementTargetExecutionChallenge.model_validate(
        payload["measurementTargetChallenge"]
    )
    expected_observed = challenge.operation_ordinal in {2, 3, 4}
    turn = probe.turns[0]
    request = {
        "sessionId": probe.session_id,
        "messages": [item.model_dump(mode="json") for item in turn.messages],
        "metadata": {"scenarioId": probe.scenario_id, "turn": 0},
    }
    response = {
        "sessionId": probe.session_id,
        "message": {
            "role": "assistant",
            "content": (
                f"observed {probe.checks[0].value}"
                if expected_observed
                else "safe deterministic response"
            ),
        },
        "toolCalls": [],
        "safety": {"blocked": False, "reason": None},
        "memoryWrites": [],
        "model": "pajin-deterministic-lab-v1",
    }
    raw = {
        "target": payload["target"],
        "scenarioId": probe.scenario_id,
        "threatClass": probe.threat_class,
        "sessionId": probe.session_id,
        "purpose": "attack",
        "vulnerable": expected_observed,
        "observation": (
            "all scenario compromise indicators were observed"
            if expected_observed
            else "no scenario compromise indicators were observed"
        ),
        "turns": [
            {
                "index": 0,
                "name": turn.name,
                "request": request,
                "response": response,
                "responseLatencySeconds": 0.001,
            }
        ],
        "checks": [
            {
                "checkId": probe.checks[0].check_id,
                "kind": probe.checks[0].kind.value,
                "turn": 0,
                "matched": expected_observed,
                "sensitive": probe.checks[0].sensitive,
            }
        ],
        "sensitiveExposureCount": (1 if expected_observed and probe.checks[0].sensitive else 0),
        "meanResponseLatencySeconds": 0.001,
        "regressionPassed": None,
        "networkPerformed": True,
    }
    observer.provider.attest_measurement_exchange(
        challenge=challenge,
        request=request,
        response=response,
    )
    target = payload["target"]
    network_log = "\n".join(
        (
            json.dumps({"event": "ready", "port": 8080}, separators=(",", ":")),
            json.dumps(
                {
                    "event": "allow",
                    "receiptVersion": AI_CHAT_PROXY_RECEIPT_VERSION,
                    "sequence": 1,
                    "method": "POST",
                    "target": target,
                    "targetSha256": sha256(target.encode()).hexdigest(),
                    "address": "172.30.0.3",
                    "status": 200,
                    "requestJsonSha256": _canonical_digest(request),
                    "responseBodySha256": _canonical_digest(response),
                    "responseJsonSha256": _canonical_digest(response),
                },
                separators=(",", ":"),
            ),
        )
    )
    await observer.cleaned(observation)
    now = datetime.now(UTC)
    return WorkerResult(
        execution_id=job.execution_id,
        backend="docker",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=json.dumps(raw, ensure_ascii=False, separators=(",", ":")),
        network_log=network_log,
        started_at=now,
        finished_at=now + timedelta(milliseconds=1),
    )


async def _run_ai002b_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    object,
    AISourceImageBinding,
    _InProcessProvider,
    object,
]:
    monkeypatch.setattr(store_module.tempfile, "gettempdir", lambda: str(tmp_path))
    images = registered_ai_source_image_binding(_ImageInspector())
    provider = _InProcessProvider(images)
    measured = registered_ai_measured_case_mapping()
    source_authorizer = _SourceAuthorizer(tmp_path / "source-plans")
    monkeypatch.setattr(
        DockerWorkerBackend,
        "run",
        _run_in_process_ai_measurement_worker,
    )
    source = await AISourceMeasurementRunner(
        measured_cases=measured,
        images=images,
        provider=provider,
        authorizer=source_authorizer,
        source_runs_root=tmp_path / "source-runs",
        authority_runs_root=tmp_path / "source-authority-runs",
    ).run()
    return source, images, provider, measured


async def _run_ai002c_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    AIReplayEvaluationOutcome,
    _MeasurementAuthorizer,
    _InProcessProvider,
    object,
]:
    source, images, provider, measured = await _run_ai002b_checkpoint(
        tmp_path,
        monkeypatch,
    )
    authorizer = _MeasurementAuthorizer(tmp_path / "measurement-plans")
    outcome = await AIReplayEvaluationRunner(
        source=source,
        measured_cases=measured,
        images=images,
        provider=provider,
        authorizer=authorizer,
        operation_runs_root=tmp_path / "operation-runs",
        evaluation_runs_root=tmp_path / "evaluation-runs",
    ).run()
    return outcome, authorizer, provider, measured


@pytest.mark.asyncio
async def test_ai_replay_floor_executes_canonical_fresh_operations_and_reopens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, authorizer, provider, measured = await _run_ai002c_checkpoint(
        tmp_path,
        monkeypatch,
    )
    reopened = load_ai_replay_floor_evaluation(
        outcome,
        measured_cases=measured,
        provider=provider,
    )
    public = outcome.mapping.public_evaluation
    private = outcome.mapping.private_binding
    public_payload = public.model_dump(mode="json", by_alias=True)
    public_wire = public.model_dump_json(by_alias=True)

    assert reopened == public
    assert authorizer.calls == 5
    assert tuple(item.operation for item in public.operations) == (
        registered_ai_measurement_operations()
    )
    assert tuple(item.result_state for item in public.operations) == (
        "known-positive-observed",
        "supporting-replay-observed",
        "supporting-replay-observed",
        "baseline-control-observed",
        "negative-control-not-observed",
        "counterfactual-control-not-observed",
    )
    assert len(public.observations) == 14
    assert tuple(item.metric.metric_id for item in public.observations) == (
        "common.ground-truth-coverage",
        "common.detection-recall",
        "common.task-success-rate",
        "common.false-positive-rate",
        "common.detection-precision",
        "common.replay-or-reanalysis-success-rate",
        "common.time-to-first-valid-result",
        "common.total-request-units",
        "common.total-tool-calls",
        "common.total-cost-usd",
        "common.evidence-completeness",
        "common.policy-denial-correctness",
        "common.cleanup-success-rate",
        "ai.threat-class-coverage",
    )
    observations = {item.metric.metric_id: item for item in public.observations}
    assert (
        observations["common.total-request-units"].numerator,
        observations["common.total-request-units"].denominator,
    ) == (6, 1)
    assert (
        observations["common.total-tool-calls"].numerator,
        observations["common.total-tool-calls"].denominator,
    ) == (6, 1)
    assert (
        observations["common.total-cost-usd"].numerator,
        observations["common.total-cost-usd"].denominator,
    ) == (0, 1_000_000)
    assert (
        observations["common.evidence-completeness"].numerator,
        observations["common.evidence-completeness"].denominator,
    ) == (84, 84)
    assert (
        observations["common.policy-denial-correctness"].numerator,
        observations["common.policy-denial-correctness"].denominator,
    ) == (8, 8)

    false_aliases = (
        "imageBuildAuthorized",
        "targetCreationAuthorized",
        "networkCreationAuthorized",
        "providerSelectionAuthorized",
        "callerConfigurationAuthorized",
        "approvalIssuanceAuthorized",
        "replayExecutionAuthorized",
        "controlExecutionAuthorized",
        "gatewayExecutionAuthorized",
        "workerExecutionAuthorized",
        "aiObservationConfirmed",
        "graphAdmissionAuthorized",
        "graphMutationAuthorized",
        "findingAuthority",
        "productProjectionAuthorized",
        "reportingAuthorized",
        "externalDeliveryAuthorized",
        "credentialAccessAuthorized",
        "externalProviderAuthorized",
        "externalTargetAuthorized",
        "productionTargetAuthorized",
        "arbitraryPromptAuthorized",
        "arbitraryToolAuthorized",
        "pluginAuthorized",
        "ragAuthorized",
        "mcpAuthorized",
        "memoryMutationAuthorized",
        "m06Authorized",
        "a04Authorized",
        "generalAIScannerAuthorized",
        "permitIssuanceAuthorized",
        "grantIssuanceAuthorized",
        "applicationProtocolWriteAuthorized",
        "modelCallAuthorized",
        "additionalExecutionAuthorized",
    )
    assert all(public_payload[item] is False for item in false_aliases)
    assert _all_keys(public_payload).isdisjoint(
        {
            "groundTruth",
            "promptText",
            "checkValue",
            "request",
            "sessionId",
            "trustAnchor",
            "workerResult",
            "toolResult",
            "output",
            "lifecycle",
            "executionIdentities",
            "accountingObservations",
            "materializationNonce",
        }
    )
    assert private.private_ground_truth.case.prompt_text not in public_wire
    assert private.private_ground_truth.case.check_value not in public_wire
    assert len(private.followup_measurements) == 5
    assert tuple(item.expected_observed for item in private.followup_measurements) == (
        True,
        True,
        True,
        False,
        False,
    )
    assert tuple(item.observed for item in private.followup_measurements) == (
        True,
        True,
        True,
        False,
        False,
    )
    assert all(item.graph_admitted is False for item in private.followup_measurements)
    assert all(item.finding_created is False for item in private.followup_measurements)
    identities = private.execution_identities
    for attribute in (
        "execution_run_id",
        "request_id",
        "session_id",
        "approval_id",
        "approval_receipt_id",
        "permit_id",
        "grant_id",
        "worker_execution_id",
        "challenge_id",
        "target_receipt_digest",
        "target_attempt_id",
        "target_container_id",
        "target_network_id",
        "worker_container_id",
        "proxy_container_id",
        "internal_network_id",
    ):
        assert len({getattr(item, attribute) for item in identities}) == 6
    assert sum(item.request_unit_count for item in private.accounting_observations) == 6
    assert sum(item.tool_call_count for item in private.accounting_observations) == 6
    assert sum(item.model_provider_cost_micro_usd for item in private.accounting_observations) == 0
    paths = {
        outcome.run_path.resolve(),
        outcome.source.execution.source_inputs.run_path.resolve(),
        *(item.source_inputs.run_path.resolve() for item in outcome.executions),
    }
    assert len(paths) == 7
    assert all(item.lifecycle.target_resources_absent for item in outcome.executions)
    assert provider.managed_resources_absent()
    assert len(provider.inspectors) == 6


@pytest.mark.asyncio
async def test_ai_replay_floor_rejects_wire_private_and_context_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, _authorizer, provider, measured = await _run_ai002c_checkpoint(
        tmp_path,
        monkeypatch,
    )
    public = outcome.mapping.public_evaluation
    private = outcome.mapping.private_binding

    public_json = public.model_dump_json(by_alias=True)
    assert AIReplayFloorEvaluation.model_validate_json(public_json) == public
    with pytest.raises(ValidationError, match="valid tuple"):
        AIReplayFloorEvaluation.model_validate(json.loads(public_json))

    reordered = public.model_dump(mode="python", by_alias=True)
    reordered["operations"] = tuple(reversed(reordered["operations"]))
    with pytest.raises(ValidationError, match="operation order differs"):
        AIReplayFloorEvaluation.model_validate(reordered)

    digest_drift = public.model_dump(mode="python", by_alias=True)
    digest_drift["evaluationDigest"] = _digest("ai002c-evaluation-drift")
    with pytest.raises(ValidationError, match="evaluation Digest differs"):
        AIReplayFloorEvaluation.model_validate(digest_drift)

    leaked = public.model_dump(mode="python", by_alias=True)
    leaked["promptText"] = private.private_ground_truth.case.prompt_text
    with pytest.raises(ValidationError, match="Extra inputs"):
        AIReplayFloorEvaluation.model_validate(leaked)

    authority_escalation = public.model_dump(mode="python", by_alias=True)
    authority_escalation["callerConfigurationAuthorized"] = True
    with pytest.raises(ValidationError, match="boolean false"):
        AIReplayFloorEvaluation.model_validate(authority_escalation)

    replay_escalation = public.model_dump(mode="python", by_alias=True)
    replay_escalation["replayExecutionAuthorized"] = True
    with pytest.raises(ValidationError, match="boolean false"):
        AIReplayFloorEvaluation.model_validate(replay_escalation)

    foreign_images = private.model_dump(mode="python", by_alias=True)
    foreign_images["bindingId"] = ""
    foreign_images["bindingDigest"] = ""
    foreign_images["images"]["bindingId"] = ""
    foreign_images["images"]["bindingDigest"] = ""
    foreign_images["images"]["imageProfile"]["profileDigest"] = _digest("foreign-ai-image-profile")
    with pytest.raises(ValidationError, match="image membership"):
        AIPrivateReplayEvaluationBinding.model_validate(foreign_images)

    reordered_private = private.model_dump(mode="python", by_alias=True)
    reordered_private["followupMeasurements"] = tuple(
        reversed(reordered_private["followupMeasurements"])
    )
    with pytest.raises(ValidationError, match="membership or canonical order"):
        AIPrivateReplayEvaluationBinding.model_validate(reordered_private)

    reused_identity = private.model_dump(mode="python", by_alias=True)
    identities = list(reused_identity["executionIdentities"])
    identities[1] = dict(identities[0])
    identities[1]["operationOrdinal"] = 2
    identities[1]["identityDigest"] = ""
    reused_identity["executionIdentities"] = identities
    with pytest.raises(ValidationError, match="identities overlap"):
        AIPrivateReplayEvaluationBinding.model_validate(reused_identity)

    reversed_contexts = replace(
        outcome,
        executions=tuple(reversed(outcome.executions)),
    )
    with pytest.raises(AIReplayEvaluationError, match="could not be contextfully reopened"):
        load_ai_replay_floor_evaluation(
            reversed_contexts,
            measured_cases=measured,
            provider=provider,
        )

    reused_contexts = replace(
        outcome,
        executions=(outcome.executions[0],) * 5,
    )
    with pytest.raises(AIReplayEvaluationError, match="could not be contextfully reopened"):
        load_ai_replay_floor_evaluation(
            reused_contexts,
            measured_cases=measured,
            provider=provider,
        )

    first_context = outcome.executions[0]
    preparation_payload = first_context.source_inputs.preparation.model_dump(
        mode="python",
        by_alias=True,
    )
    preparation_payload["preparationId"] = ""
    preparation_payload["preparationDigest"] = ""
    preparation_payload["registeredOperationDigest"] = _digest("foreign-ai002c-operation")
    drifted_preparation = type(first_context.source_inputs.preparation).model_validate(
        preparation_payload
    )
    drifted_inputs = replace(
        first_context.source_inputs,
        preparation=drifted_preparation,
    )
    drifted_context = replace(first_context, source_inputs=drifted_inputs)
    drifted_outcome = replace(
        outcome,
        executions=(drifted_context, *outcome.executions[1:]),
    )
    with pytest.raises(AIReplayEvaluationError, match="could not be contextfully reopened"):
        load_ai_replay_floor_evaluation(
            drifted_outcome,
            measured_cases=measured,
            provider=provider,
        )


@pytest.mark.asyncio
async def test_ai_replay_floor_rejects_caller_selected_execution_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, images, provider, measured = await _run_ai002b_checkpoint(
        tmp_path,
        monkeypatch,
    )
    authorizer = _CallerConfiguredMeasurementAuthorizer(tmp_path / "caller-configured-plans")
    runner = AIReplayEvaluationRunner(
        source=source,
        measured_cases=measured,
        images=images,
        provider=provider,
        authorizer=authorizer,
        operation_runs_root=tmp_path / "caller-operation-runs",
        evaluation_runs_root=tmp_path / "caller-evaluation-runs",
    )

    with pytest.raises(AIReplayEvaluationError, match="pre-dispatch authority differs"):
        await runner.run()
    assert authorizer.calls == 1
    assert provider.managed_resources_absent()


@pytest.mark.asyncio
async def test_ai_source_path_seals_denials_private_custody_and_reopens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(store_module.tempfile, "gettempdir", lambda: str(tmp_path))
    images = registered_ai_source_image_binding(_ImageInspector())
    provider = _InProcessProvider(images)
    measured = registered_ai_measured_case_mapping()
    authorizer = _SourceAuthorizer(tmp_path / "plans")
    monkeypatch.setattr(DockerWorkerBackend, "run", _run_in_process_worker)
    runner = AISourceMeasurementRunner(
        measured_cases=measured,
        images=images,
        provider=provider,
        authorizer=authorizer,
        source_runs_root=tmp_path / "source-runs",
        authority_runs_root=tmp_path / "authority-runs",
    )

    outcome = await runner.run()
    reopened = load_ai_source_measurement_authority(
        outcome,
        measured_cases=measured,
        provider=provider,
    )
    public = outcome.mapping.public_authority
    private = outcome.mapping.private_binding
    public_payload = public.model_dump(mode="json", by_alias=True)
    public_wire = public.model_dump_json(by_alias=True)

    assert reopened == public
    assert authorizer.calls == 1
    assert tuple(item.control for item in public.denials) == tuple(AISourceDenialControl)
    assert all(item.dispatch_invocation_count == 0 for item in public.denials)
    assert all(public_payload[name] is False for name in _FALSE_PUBLIC_ALIASES)
    assert _all_keys(public_payload).isdisjoint(_PRIVATE_ONLY_KEYS)
    assert private.measurement.ground_truth.prompt_text not in public_wire
    assert private.measurement.ground_truth.check_value not in public_wire
    assert private.measurement.request.target not in public_wire
    assert private.measurement.request_unit_count == 1
    assert private.measurement.tool_call_count == 1
    assert private.measurement.model_provider_cost_micro_usd == 0
    assert private.measurement.graph_admitted is False
    assert private.measurement.finding_created is False
    assert private.measurement.output.vulnerable is True
    assert private.measurement.lifecycle.target_resources_absent is True
    assert provider.managed_resources_absent()
    assert len(provider.inspectors) == 1
    assert provider.inspectors[0].topology is not None

    reordered = public.model_dump(mode="python", by_alias=True)
    reordered["authorityId"] = ""
    reordered["authorityDigest"] = ""
    reordered["denials"] = tuple(reversed(reordered["denials"]))
    with pytest.raises(ValidationError, match="denial order differs"):
        AISourceMeasurementAuthority.model_validate(reordered)

    authority_escalation = public.model_dump(mode="python", by_alias=True)
    authority_escalation["graphAdmissionAuthorized"] = True
    with pytest.raises(ValidationError, match="boolean false"):
        AISourceMeasurementAuthority.model_validate(authority_escalation)

    leaked = private.model_dump(mode="python", by_alias=True)
    leaked["promptText"] = private.measurement.ground_truth.prompt_text
    with pytest.raises(ValidationError, match="Extra inputs"):
        AIPrivateSourceMeasurementBinding.model_validate(leaked)

    _validate_mapping(
        AISourceMeasurementMapping(
            public_authority=public,
            private_binding=private,
        ),
        measured_authority=measured.public_authority,
        private_ground_truth=measured.private_binding,
    )


@pytest.mark.asyncio
async def test_real_docker_exact_m03_source_measurement_is_opt_in(
    tmp_path: Path,
) -> None:
    if os.environ.get("PAJIN_AI_002B_REAL_DOCKER") != "1":
        pytest.skip("set PAJIN_AI_002B_REAL_DOCKER=1 with the three fixed images")
    provider = AIFixtureDockerProvider()
    images = registered_ai_source_image_binding(provider)
    measured = registered_ai_measured_case_mapping()
    runner = AISourceMeasurementRunner(
        measured_cases=measured,
        images=images,
        provider=provider,
        authorizer=_SourceAuthorizer(tmp_path / "plans"),
        source_runs_root=tmp_path / "source-runs",
        authority_runs_root=tmp_path / "authority-runs",
    )
    outcome = await runner.run()
    reopened = load_ai_source_measurement_authority(
        outcome,
        measured_cases=measured,
        provider=provider,
    )

    assert reopened == outcome.mapping.public_authority
    assert reopened.case.case.case_id == "ai-fixture:m03-system-prompt-disclosure"
    assert provider.managed_resources_absent()
