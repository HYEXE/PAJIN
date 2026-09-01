from __future__ import annotations

import json
import os
from collections.abc import Mapping
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
    registered_ai_measured_case_mapping,
    registered_ai_private_ground_truth_case,
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
            workerImageId=self.images.role(
                AIMeasurementImageRole.WORKER
            ).observed_image_id,
            proxyContainerName=observation.proxy_container_name,
            proxyContainerId=_digest(f"proxy:{observation.execution_id}"),
            proxyImageId=self.images.role(
                AIMeasurementImageRole.PROXY
            ).observed_image_id,
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
            targetImageId=images.role(
                AIMeasurementImageRole.TARGET
            ).observed_image_id,
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
        self.receipt = None
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
    authorizer: _SourceAuthorizer,
) -> AISourceApprovedAction:
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
    preparation = prepare_ai_read_only_analysis(
        activation=activation,
        release=release,
        binding=binding,
        request=request,
        provider_registration=provider,
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
        authority_context_digest=_canonical_authority_context(authorizer)[1],
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
        return _approved_plan(
            self.root / f"plan-{self.calls}",
            target=target,
            run_id=run_id,
            request_id=request_id,
            authorizer=self,
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
    challenge = AISourceTargetExecutionChallenge.model_validate(
        payload["sourceTargetChallenge"]
    )
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
