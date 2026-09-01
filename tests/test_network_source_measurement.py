from __future__ import annotations

import json
import os
from base64 import b64decode, b64encode
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_network_fixture_runtime import _FakeDocker, _runtime, _topology
from test_network_service_admission import (
    DIGEST_A,
    DIGEST_B,
    DIGEST_C,
    DIGEST_D,
    NOW,
    _ApprovalInputAuthority,
    _graph_authority,
)
from test_network_service_identification import _activation, _campaign, _surface

from pajin.capabilities.network_service import prepare_network_service_identification
from pajin.control_plane.executors import CapabilityGraphCampaignJobInput
from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CapabilityGrant,
    ToolResult,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.graph.approval import (
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalEnvelope,
    ActionApprovalIssuerAuthorityBinding,
    ActionApprovalReleaseRef,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
)
from pajin.graph.authority import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionPermit,
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
from pajin.tools.base import EGRESS_HTTPS_CONNECT_RECEIPT_VERSION
from pajin.tools.network import network_service_scope_allow_rule
from pajin.workflow.network_fixture_runtime import (
    NETWORK_WORKER_IMAGE,
    NetworkFixtureDockerProvider,
    NetworkFixtureOperationJournal,
    NetworkFixtureTargetCoordinate,
    NetworkFixtureTargetLifecycleEvidence,
    NetworkFixtureTargetLifecycleRunner,
    NetworkSourceImageBinding,
    registered_network_source_image_binding,
)
from pajin.workflow.network_measured_case_authority import (
    NetworkMeasuredCaseMapping,
    NetworkMeasuredCaseRef,
    NetworkMeasurementImageRole,
    NetworkPrivateGroundTruthCase,
    registered_network_measured_case_mapping,
)
from pajin.workflow.network_source_measurement import (
    NetworkPrivateSourceCaseMeasurement,
    NetworkPrivateSourceMeasurementBinding,
    NetworkSourceApprovedAction,
    NetworkSourceDenialControl,
    NetworkSourceDenialReceipt,
    NetworkSourceMeasurementAuthority,
    NetworkSourceMeasurementError,
    NetworkSourceMeasurementMapping,
    NetworkSourceMeasurementRunner,
    _build_public_lineage,
    _canonical_authority_context,
    _canonical_backend_context,
    _evaluate_code_owned_denials,
    _validate_mapping,
    _validate_source_pre_dispatch,
    load_network_source_measurement_authority,
)

_ISSUER = ActionApprovalIssuerAuthorityBinding(
    authorityId="deployment:network-source-approval",
    authorityVersion="1.0.0",
    implementationType="tests.network_source.ExternalApprovalAuthority",
    contextDigest=DIGEST_D,
)
_DENIAL_ORDER = (
    NetworkSourceDenialControl.SCOPE_SUBSTITUTION,
    NetworkSourceDenialControl.CASE_SUBSTITUTION,
    NetworkSourceDenialControl.ROUTE_SUBSTITUTION,
    NetworkSourceDenialControl.IMAGE_SUBSTITUTION,
    NetworkSourceDenialControl.AUTHORITY_SUBSTITUTION,
)
_PUBLIC_FALSE_MARKERS = (
    "replayAuthorized",
    "measurementFloorEvaluated",
    "validationFloorSatisfied",
    "serviceConfirmationAuthorized",
    "graphAdmissionAuthorized",
    "graphMutationAuthorized",
    "findingAuthority",
    "productProjectionAuthorized",
    "reportingAuthorized",
    "externalDeliveryAuthorized",
    "dnsAuthorized",
    "udpAuthorized",
    "portRangeAuthorized",
    "portEnumerationAuthorized",
    "rawSocketAuthorized",
    "applicationProtocolWriteAuthorized",
    "credentialAccessAuthorized",
    "externalTargetAuthorized",
    "productionTargetAuthorized",
    "generalScannerAuthorized",
    "callerConfigurationAuthorized",
    "additionalExecutionAuthorized",
)
_PUBLIC_PRIVATE_KEYS = {
    "rawBannerBase64",
    "observedServiceName",
    "workerResult",
    "toolResult",
    "lifecycle",
    "targetContainerName",
    "targetNetworkName",
    "host",
    "port",
}


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


class _StableAuthority:
    def stable_authority_context(self) -> Mapping[str, object]:
        return {
            "authorityId": "deployment:network-source-authorizer",
            "authorityVersion": "1.0.0",
            "approvalIssuer": _ISSUER.model_dump(mode="json", by_alias=True),
        }


def _authority_context() -> tuple[dict[str, object], str]:
    return _canonical_authority_context(_StableAuthority())


def _exact_campaign(
    sample_campaign: CampaignManifest,
    target: NetworkFixtureTargetCoordinate,
) -> CampaignManifest:
    campaign = _campaign(
        sample_campaign,
        allow=[
            network_service_scope_allow_rule(
                address_family=target.address_family,
                host=target.host,
                port=target.port,
            )
        ],
        connect_allowed=True,
        allow_private_networks=True,
    )
    payload = campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["rulesOfEngagement"]["allowedMethods"] = ["CONNECT"]
    return CampaignManifest.model_validate(payload)


def _approved_plan(
    root: Path,
    sample_campaign: CampaignManifest,
    *,
    target: NetworkFixtureTargetCoordinate,
    run_id: str,
    request_id: str,
    clock_base: datetime,
) -> NetworkSourceApprovedAction:
    root.mkdir(parents=True, exist_ok=True)
    activation, release = _activation()
    campaign = _exact_campaign(sample_campaign, target)
    preparation = prepare_network_service_identification(
        activation=activation,
        release=release,
        campaign=campaign,
        surface=_surface(host=target.host, port=target.port),
        request_id=request_id,
        agent_id="agent:network-source",
    )
    prepared = preparation.prepared_action
    graph_store, _admission, _lineages, _binding, decision = _graph_authority(
        root,
        campaign.metadata.name,
        decision_payload_digest=preparation.preparation_digest,
    )
    target_digest = sha256(prepared.request.target.encode()).hexdigest()
    capability = activation.activation_set.binding.action_capability
    proposal_at = max(
        decision.created_at + timedelta(seconds=1),
        clock_base - timedelta(seconds=3),
    )
    approval_at = max(
        proposal_at + timedelta(seconds=1),
        clock_base - timedelta(seconds=2),
    )
    approval_not_before = max(
        approval_at + timedelta(seconds=1),
        clock_base - timedelta(seconds=1),
    )
    envelope = MissionEnvelope(
        campaignId=campaign.metadata.name,
        runId=run_id,
        profileId="network-source-passive-v1",
        profileVersion="1.0.0",
        profileDigest=DIGEST_A,
        compilerId="pajin.network.source-action-compiler",
        compilerVersion="1.0.0",
        compilerDigest=DIGEST_B,
        sourceCampaignDigest=campaign_manifest_digest(campaign),
        allowedCapabilities=(capability.reference(),),
        allowedTargetDigests=(target_digest,),
        maxRiskTier=ToolRiskTier.T2,
        budget=ActionBudgetLimit(toolCallLimit=1, requestUnitLimit=1),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=clock_base - timedelta(seconds=4),
        notBefore=clock_base - timedelta(seconds=3),
        expiresAt=clock_base + timedelta(minutes=2),
    )
    proposal = ActionProposal(
        campaignId=campaign.metadata.name,
        runId=run_id,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=decision.snapshot,
        proposerId="pajin.graph.network-source-planner",
        proposerDigest=DIGEST_C,
        capability=prepared.capability,
        targetDigest=target_digest,
        requestId=prepared.request.request_id,
        requestDigest=prepared.request_digest,
        normalizedParametersDigest=prepared.normalized_parameters_digest,
        riskTier=ToolRiskTier.T2,
        reservation=ActionBudgetReservation(requestUnits=1),
        createdAt=proposal_at,
    )
    approval = ActionApprovalEnvelope(
        issuer=_ISSUER,
        requestedBy="principal:network-source-requester",
        approvedBy="principal:network-source-approver",
        campaignId=campaign.metadata.name,
        campaignDigest=campaign_manifest_digest(campaign),
        runId=run_id,
        missionEnvelope=envelope,
        sourceIntentDigest=preparation.preparation_digest,
        activationSetDigest=prepared.activation_set_digest,
        release=ActionApprovalReleaseRef(
            releaseId=release.release_id,
            releaseDigest=release.release_digest,
            capabilityId=prepared.capability.capability_id,
            capabilityVersion=prepared.capability.capability_version,
            capabilityDigest=prepared.capability.definition_digest,
        ),
        graphDecision=decision,
        proposal=proposal,
        expectedActionPermitId=action_permit_attempt_id(envelope, proposal, decision),
        sideEffectClass="read-only",
        reservation=proposal.reservation,
        approvedAt=approval_at,
        notBefore=approval_not_before,
        expiresAt=clock_base + timedelta(minutes=1),
    )
    grant = CapabilityGrant(
        grant_id=f"grant_network_source_{_digest(run_id)[:16]}",
        subject=prepared.request.agent_id,
        campaign=campaign.metadata.name,
        tools={prepared.request.tool_id},
        targets={prepared.request.target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        issued_at=clock_base - timedelta(seconds=5),
        expires_at=clock_base + timedelta(minutes=1),
    )
    job = CapabilityGraphCampaignJobInput(
        profile="capability-graph-v1",
        proposal=proposal,
        decision=decision,
        release=release,
        request=prepared.request,
        grant=grant,
        approval=approval,
    )
    _context, context_digest = _authority_context()
    return NetworkSourceApprovedAction(
        activation=activation,
        campaign=campaign,
        preparation=preparation,
        job=job,
        mission_envelope=envelope,
        graph_store=graph_store,
        approval_input_authority=_ApprovalInputAuthority(approval),
        approval_issuer=_ISSUER,
        authority_context_digest=context_digest,
    )


@dataclass(frozen=True)
class _SyntheticSource:
    mapping: NetworkSourceMeasurementMapping
    measured: NetworkMeasuredCaseMapping
    images: NetworkSourceImageBinding
    provider: NetworkFixtureDockerProvider


def _private_case(
    *,
    ordinal: int,
    ground_truth: NetworkPrivateGroundTruthCase,
    lifecycle: NetworkFixtureTargetLifecycleEvidence,
) -> NetworkPrivateSourceCaseMeasurement:
    raw = b64decode(ground_truth.fixture.banner_base64)
    now = datetime.now(UTC)
    data: dict[str, object] = {
        "connected": True,
        "host": lifecycle.coordinate.host,
        "port": lifecycle.coordinate.port,
        "bannerBase64": ground_truth.fixture.banner_base64,
        "bannerSha256": ground_truth.fixture.banner_sha256,
        "bannerBytes": len(raw),
    }
    if ground_truth.fixture.expected_service_name is not None:
        data["serviceName"] = ground_truth.fixture.expected_service_name
    execution_id = lifecycle.topology.execution_id
    worker_result = WorkerResult(
        execution_id=execution_id,
        backend="docker",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=json.dumps(data, separators=(",", ":")),
        network_log="private-trusted-connect-receipt",
        started_at=now,
        finished_at=now + timedelta(milliseconds=1),
    )
    tool_result = ToolResult(
        request_id=f"tool_net002b_source_{ordinal}",
        tool_id="network-service-identify",
        success=True,
        started_at=worker_result.started_at,
        finished_at=worker_result.finished_at,
        data=data,
    )
    return NetworkPrivateSourceCaseMeasurement(
        case=ground_truth,
        sourceRunId=f"run_net002b_source_{ordinal}",
        sourceRootDigest=_digest(f"source-root:{ordinal}"),
        approvalReceiptId=f"approval_receipt_net002b_{ordinal}",
        approvalReceiptDigest=_digest(f"approval-receipt:{ordinal}"),
        permitId=f"permit_net002b_{ordinal}",
        permitDigest=_digest(f"permit:{ordinal}"),
        reservationPath=f"action-budget/network-source-{ordinal}.json",
        reservationSha256=_digest(f"reservation:{ordinal}"),
        executionEvidencePath=f"evidence/network-source-{ordinal}.json",
        executionEvidenceSha256=_digest(f"execution:{ordinal}"),
        lifecycle=lifecycle,
        workerResult=worker_result,
        toolResult=tool_result,
        rawBannerBase64=ground_truth.fixture.banner_base64,
        observedServiceName=ground_truth.fixture.expected_service_name,
    )


def _synthetic_source(tmp_path: Path) -> _SyntheticSource:
    measured = registered_network_measured_case_mapping()
    docker, provider, images = _runtime()
    lifecycle_runner = NetworkFixtureTargetLifecycleRunner(
        provider=provider,
        journal=NetworkFixtureOperationJournal(tmp_path / "fixture-journal.sqlite3"),
    )
    private_cases: list[NetworkPrivateSourceCaseMeasurement] = []
    for ordinal, (case, ground_truth) in enumerate(
        zip(
            measured.public_authority.public_registry.cases,
            measured.private_binding.cases,
            strict=True,
        ),
        start=1,
    ):
        live = lifecycle_runner.start(case=case.reference(), images=images)
        docker.banner_emitted = True
        topology = _topology(
            execution_id=f"exec_network_source_{ordinal}",
            target_container_id=live.coordinate.target_container_id,
            target_image_id=live.coordinate.target_image_id,
            target_network_name=live.coordinate.target_network_name,
            target_network_id=live.coordinate.target_network_id,
            worker_container_id=_digest(f"worker:{ordinal}"),
            proxy_container_id=_digest(f"proxy:{ordinal}"),
            internal_network_id=_digest(f"internal-network:{ordinal}"),
        )
        private_cases.append(
            _private_case(
                ordinal=ordinal,
                ground_truth=ground_truth,
                lifecycle=lifecycle_runner.finish(live, topology=topology),
            )
        )
    public = NetworkSourceMeasurementAuthority(
        measuredCaseAuthority=measured.public_authority.reference(),
        measurementProtocol=measured.public_authority.measurement_protocol.reference(),
        privateGroundTruthBindingDigest=measured.private_binding.binding_digest,
        images=images.reference(),
        actionAuthorityContextDigest=_authority_context()[1],
        cases=tuple(_build_public_lineage(item) for item in private_cases),
        denials=tuple(NetworkSourceDenialReceipt(control=item) for item in _DENIAL_ORDER),
    )
    private = NetworkPrivateSourceMeasurementBinding(
        publicAuthority=public.reference(),
        privateGroundTruthBindingId=measured.private_binding.binding_id,
        privateGroundTruthBindingDigest=measured.private_binding.binding_digest,
        images=images,
        cases=tuple(private_cases),
    )
    return _SyntheticSource(
        mapping=NetworkSourceMeasurementMapping(
            public_authority=public,
            private_binding=private,
        ),
        measured=measured,
        images=images,
        provider=provider,
    )


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_all_keys(item) for item in value.values()), set())
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value), set())
    return set()


def test_source_mapping_is_exact_canonical_and_public_safe(tmp_path: Path) -> None:
    source = _synthetic_source(tmp_path)
    public = source.mapping.public_authority
    private = source.mapping.private_binding

    _validate_mapping(
        source.mapping,
        measured_authority=source.measured.public_authority,
        private_ground_truth=source.measured.private_binding,
    )
    expected_case_ids = (
        "network-fixture:ftp-known-positive",
        "network-fixture:imap-known-positive",
        "network-fixture:pop3-known-positive",
        "network-fixture:smtp-known-positive",
        "network-fixture:ssh-known-positive",
        "network-fixture:unknown-negative-control",
    )
    assert tuple(item.case.case_id for item in public.cases) == expected_case_ids
    assert tuple(item.case.case_id for item in private.cases) == expected_case_ids
    assert tuple(item.control for item in public.denials) == _DENIAL_ORDER
    assert all(item.dispatch_invocation_count == 0 for item in public.denials)
    assert len({item.lifecycle.attempt.attempt_id for item in private.cases}) == 6
    assert len({item.lifecycle.coordinate.target_container_id for item in private.cases}) == 6
    assert len({item.lifecycle.coordinate.target_network_id for item in private.cases}) == 6
    assert all(item.lifecycle.target_banner_emission_count == 1 for item in private.cases)
    assert all(item.lifecycle.target_application_read_bytes == 0 for item in private.cases)
    assert all(item.connect_receipt_count == 1 for item in private.cases)
    assert all(item.application_write_bytes == 0 for item in private.cases)

    public_payload = public.model_dump(mode="json", by_alias=True)
    public_json = public.model_dump_json(by_alias=True)
    assert _all_keys(public_payload).isdisjoint(_PUBLIC_PRIVATE_KEYS)
    assert all(
        item.fixture.banner_base64 not in public_json
        for item in source.measured.private_binding.cases
    )
    assert all(public_payload[field] is False for field in _PUBLIC_FALSE_MARKERS)
    image_payload = private.images.model_dump(mode="json", by_alias=True)
    assert image_payload["dockerImageBuildAuthorized"] is False
    assert image_payload["callerSelectedImageAuthorized"] is False

    unknown = private.cases[-1]
    assert unknown.case.expected_classifier_outcome == "protocol-label-unresolved"
    assert unknown.case.fixture.expected_service_name is None
    assert unknown.observed_service_name is None
    assert "serviceName" not in unknown.tool_result.data


def test_source_mapping_rejects_order_substitution_digest_drift_and_unknown_label(
    tmp_path: Path,
) -> None:
    source = _synthetic_source(tmp_path)
    public = source.mapping.public_authority
    public_payload = public.model_dump(mode="json", by_alias=True)
    public_payload["cases"].reverse()
    public_payload["authorityId"] = ""
    public_payload["authorityDigest"] = ""
    reordered = NetworkSourceMeasurementAuthority.model_validate_json(json.dumps(public_payload))
    with pytest.raises(NetworkSourceMeasurementError, match="binding differs"):
        _validate_mapping(
            NetworkSourceMeasurementMapping(
                public_authority=reordered,
                private_binding=source.mapping.private_binding,
            ),
            measured_authority=source.measured.public_authority,
            private_ground_truth=source.measured.private_binding,
        )

    drifted = public.model_dump(mode="json", by_alias=True)
    drifted["cases"][0]["sourceRootDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="Digest differs"):
        NetworkSourceMeasurementAuthority.model_validate_json(json.dumps(drifted))

    unknown = source.mapping.private_binding.cases[-1]
    unknown_payload = unknown.model_dump(mode="json", by_alias=True)
    unknown_payload["caseMeasurementDigest"] = ""
    unknown_payload["observedServiceName"] = "ftp"
    unknown_payload["toolResult"]["data"]["serviceName"] = "ftp"
    with pytest.raises(ValidationError, match="Ground Truth"):
        NetworkPrivateSourceCaseMeasurement.model_validate_json(json.dumps(unknown_payload))


@pytest.mark.asyncio
async def test_predispatch_substitutions_configuration_and_reuse_never_dispatch(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    _docker, provider, images = _runtime()
    lifecycle = NetworkFixtureTargetLifecycleRunner(
        provider=provider,
        journal=NetworkFixtureOperationJournal(tmp_path / "journal.sqlite3"),
    )
    cases = tuple(
        item.reference()
        for item in (
            registered_network_measured_case_mapping().public_authority.public_registry.cases
        )
    )
    live = lifecycle.start(case=cases[0], images=images)
    plan = _approved_plan(
        tmp_path / "plan",
        sample_campaign,
        target=live.coordinate,
        run_id="run_net002b_predispatch",
        request_id="tool_net002b_predispatch",
        clock_base=NOW,
    )
    context, context_digest = _authority_context()
    inspector = provider.boundary_inspector(coordinate=live.coordinate, images=images)
    worker_image = images.role(NetworkMeasurementImageRole.WORKER)
    proxy_image = images.role(NetworkMeasurementImageRole.PROXY)
    backend = DockerWorkerBackend(
        allowed_images={NETWORK_WORKER_IMAGE},
        egress_proxy_image=proxy_image.observed_image_id,
        external_network_routes={"network-service-identify": live.coordinate.target_network_name},
        runtime_image_bindings={NETWORK_WORKER_IMAGE: worker_image.observed_image_id},
        egress_lifecycle_observer=inspector,
    )
    _validate_source_pre_dispatch(
        plan,
        expected_case=cases[0],
        target=live.coordinate,
        images=images,
        authority_context=context,
        authority_context_digest=context_digest,
        backend=backend,
        inspector=inspector,
    )
    receipts = _evaluate_code_owned_denials(
        plan,
        cases=cases,
        target=live.coordinate,
        images=images,
        authority_context=context,
        authority_context_digest=context_digest,
        backend=backend,
        inspector=inspector,
    )
    assert tuple(item.control for item in receipts) == _DENIAL_ORDER
    assert all(item.dispatch_invocation_count == 0 for item in receipts)

    caller_context = _canonical_backend_context(backend)
    caller_context["allowedImages"] = ["caller-selected:latest"]
    with pytest.raises(NetworkSourceMeasurementError, match="authority differs"):
        _validate_source_pre_dispatch(
            plan,
            expected_case=cases[0],
            target=live.coordinate,
            images=images,
            authority_context=context,
            authority_context_digest=context_digest,
            backend=backend,
            backend_context=caller_context,
            inspector=inspector,
        )

    approval = plan.job.approval
    assert approval is not None
    permit_authority = GraphApprovedActionPermitAuthority(
        campaign_id=plan.campaign.metadata.name,
        compiler_id=plan.mission_envelope.compiler_id,
        compiler_version=plan.mission_envelope.compiler_version,
        compiler_digest=plan.mission_envelope.compiler_digest,
        capabilities=plan.activation.action_registry(),
        policies=ActionApprovalCapabilityPolicyRegistry(
            (
                ActionApprovalCapabilityPolicy(
                    capability=plan.preparation.prepared_action.capability,
                    sideEffectClass="read-only",
                    approvalRequired=True,
                    cleanupRequired=False,
                ),
            )
        ),
        permit_store=plan.graph_store.permit_store,
        input_authority=plan.approval_input_authority,
        clock=lambda: NOW + timedelta(seconds=5),
    )
    dispatcher = GraphApprovedActionPermitDispatcher(permit_authority)
    dispatch_calls = 0

    async def dispatch(
        permit: ActionPermit,
        _receipt: object,
    ) -> str:
        nonlocal dispatch_calls
        dispatch_calls += 1
        return permit.permit_id

    first = await dispatcher.dispatch_once(
        plan.mission_envelope,
        plan.job.proposal,
        plan.job.decision,
        approval,
        dispatch,
    )
    second = await dispatcher.dispatch_once(
        plan.mission_envelope,
        plan.job.proposal,
        plan.job.decision,
        approval,
        dispatch,
    )
    assert first.dispatched is True
    assert second.dispatched is False
    assert dispatch_calls == 1
    with pytest.raises(NetworkSourceMeasurementError, match="reused"):
        _validate_source_pre_dispatch(
            plan,
            expected_case=cases[0],
            target=live.coordinate,
            images=images,
            authority_context=context,
            authority_context_digest=context_digest,
            backend=backend,
            inspector=inspector,
        )
    lifecycle.reconcile_abandoned()
    assert provider.managed_resources_absent()


class _DockerConformanceAuthorizer:
    def __init__(self, root: Path, sample_campaign: CampaignManifest) -> None:
        self._root = root
        self._sample_campaign = sample_campaign
        self._sequence = 0

    def stable_authority_context(self) -> Mapping[str, object]:
        return _StableAuthority().stable_authority_context()

    def authorize(
        self,
        *,
        case: NetworkMeasuredCaseRef,
        target: NetworkFixtureTargetCoordinate,
        run_id: str,
        request_id: str,
    ) -> NetworkSourceApprovedAction:
        del case
        self._sequence += 1
        return _approved_plan(
            self._root / f"case-{self._sequence}",
            self._sample_campaign,
            target=target,
            run_id=run_id,
            request_id=request_id,
            clock_base=datetime.now(UTC),
        )


class _InProcessBoundaryInspector:
    def __init__(
        self,
        *,
        coordinate: NetworkFixtureTargetCoordinate,
        images: NetworkSourceImageBinding,
        docker: _FakeDocker,
    ) -> None:
        self.coordinate = coordinate
        self.images = images
        self.docker = docker
        self.observation: DockerEgressLifecycleObservation | None = None
        self.topology = None

    def stable_observer_context(self) -> Mapping[str, object]:
        return {
            "observerId": "tests.network-source-in-process-boundary",
            "observerVersion": "1.0.0",
            "coordinateDigest": self.coordinate.coordinate_digest,
            "imageBindingDigest": self.images.binding_digest,
        }

    def image_id(self, reference: str) -> str:
        return next(
            item.observed_image_id
            for item in self.images.roles
            if item.image_reference == reference
        )

    async def attached(self, observation: DockerEgressLifecycleObservation) -> None:
        if (
            self.observation is not None
            or observation.external_network_name != self.coordinate.target_network_name
        ):
            raise RuntimeError("in-process Network topology attachment differs")
        self.observation = observation

    async def cleaned(self, observation: DockerEgressLifecycleObservation) -> None:
        if self.observation != observation or not self.docker.target_exists:
            raise RuntimeError("in-process Network topology cleanup differs")
        self.docker.banner_emitted = True
        identity = _digest(observation.execution_id)
        self.topology = _topology(
            execution_id=observation.execution_id,
            target_container_id=self.coordinate.target_container_id,
            target_image_id=self.coordinate.target_image_id,
            target_network_name=self.coordinate.target_network_name,
            target_network_id=self.coordinate.target_network_id,
            worker_container_id=_digest(f"worker:{identity}"),
            proxy_container_id=_digest(f"proxy:{identity}"),
            internal_network_id=_digest(f"network:{identity}"),
            worker_container_name=observation.worker_container_name,
            proxy_container_name=observation.proxy_container_name,
            internal_network_name=observation.internal_network_name,
        )

    def topology_observation(self, execution_id: str):
        if self.topology is None or self.topology.execution_id != execution_id:
            raise RuntimeError("in-process Network topology is incomplete")
        return self.topology.model_copy(deep=True)

    def target_resources_absent(self) -> bool:
        return not self.docker.target_exists and not self.docker.network_exists


@pytest.mark.asyncio
async def test_full_six_case_source_path_seals_and_contextfully_reopens(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker, provider, images = _runtime()
    inspectors: list[_InProcessBoundaryInspector] = []

    def boundary_inspector(
        *,
        coordinate: NetworkFixtureTargetCoordinate,
        images: NetworkSourceImageBinding,
    ) -> _InProcessBoundaryInspector:
        inspector = _InProcessBoundaryInspector(
            coordinate=coordinate,
            images=images,
            docker=docker,
        )
        inspectors.append(inspector)
        return inspector

    monkeypatch.setattr(provider, "boundary_inspector", boundary_inspector)
    private_by_case = {
        item.case_id: item
        for item in registered_network_measured_case_mapping().private_binding.cases
    }

    async def run_worker(
        backend: DockerWorkerBackend,
        job,
        *,
        secrets=None,
    ) -> WorkerResult:
        del secrets
        observer = backend._egress_lifecycle_observer
        assert isinstance(observer, _InProcessBoundaryInspector)
        identity = _digest(job.execution_id)[:16]
        observation = DockerEgressLifecycleObservation(
            execution_id=job.execution_id,
            worker_container_name=backend._container_name(job.execution_id),
            proxy_container_name=f"pajin-proxy-{identity}",
            internal_network_name=f"pajin-egress-{identity}",
            external_network_name=observer.coordinate.target_network_name,
        )
        await observer.attached(observation)
        payload = json.loads(job.stdin)
        ground_truth = private_by_case[observer.coordinate.case.case_id]
        banner = b64decode(ground_truth.fixture.banner_base64)
        output: dict[str, object] = {
            "target": payload["target"],
            "addressFamily": payload["addressFamily"],
            "host": payload["host"],
            "transportProtocol": payload["transportProtocol"],
            "port": payload["port"],
            "protocolProfile": payload["protocolProfile"],
            "connected": True,
            "bannerBytes": len(banner),
            "bannerBase64": b64encode(banner).decode("ascii"),
            "bannerSha256": sha256(banner).hexdigest(),
        }
        if ground_truth.fixture.expected_service_name is not None:
            output["serviceName"] = ground_truth.fixture.expected_service_name
        authority = f"{payload['host']}:{payload['port']}"
        network_log = "\n".join(
            (
                json.dumps({"event": "ready", "port": 8080}),
                json.dumps(
                    {
                        "event": "allow",
                        "receiptVersion": EGRESS_HTTPS_CONNECT_RECEIPT_VERSION,
                        "sequence": 1,
                        "method": "CONNECT",
                        "authority": authority,
                        "authoritySha256": sha256(authority.encode()).hexdigest(),
                        "address": payload["host"],
                        "applicationVisibility": "opaque",
                        "methodEnforcement": "trusted-worker-only",
                        "pathEnforcement": "authority-only",
                    }
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
            stdout=json.dumps(output, separators=(",", ":")),
            network_log=network_log,
            started_at=now,
            finished_at=now + timedelta(milliseconds=1),
        )

    monkeypatch.setattr(DockerWorkerBackend, "run", run_worker)
    measured = registered_network_measured_case_mapping()
    runner = NetworkSourceMeasurementRunner(
        measured_cases=measured,
        images=images,
        lifecycle=NetworkFixtureTargetLifecycleRunner(
            provider=provider,
            journal=NetworkFixtureOperationJournal(tmp_path / "journal.sqlite3"),
        ),
        authorizer=_DockerConformanceAuthorizer(tmp_path / "plans", sample_campaign),
        source_runs_root=tmp_path / "source-runs",
        authority_runs_root=tmp_path / "authority-runs",
    )
    outcome = await runner.run()
    reopened = load_network_source_measurement_authority(
        outcome,
        measured_cases=measured,
        provider=provider,
    )

    assert reopened == outcome.mapping.public_authority
    assert len(outcome.executions) == 6
    assert len(inspectors) == 6
    assert all(item.observation is not None for item in inspectors)
    assert all(item.topology is not None for item in inspectors)
    assert provider.managed_resources_absent()


@pytest.mark.asyncio
async def test_real_docker_exact_six_case_source_measurement_is_opt_in(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    if os.environ.get("PAJIN_NETWORK_002B_REAL_DOCKER") != "1":
        pytest.skip("set PAJIN_NETWORK_002B_REAL_DOCKER=1 with the three fixed images")
    provider = NetworkFixtureDockerProvider()
    images = registered_network_source_image_binding(provider)
    measured = registered_network_measured_case_mapping()
    runner = NetworkSourceMeasurementRunner(
        measured_cases=measured,
        images=images,
        lifecycle=NetworkFixtureTargetLifecycleRunner(
            provider=provider,
            journal=NetworkFixtureOperationJournal(tmp_path / "docker-journal.sqlite3"),
        ),
        authorizer=_DockerConformanceAuthorizer(tmp_path / "plans", sample_campaign),
        source_runs_root=tmp_path / "source-runs",
        authority_runs_root=tmp_path / "authority-runs",
    )
    outcome = await runner.run()
    reopened = load_network_source_measurement_authority(
        outcome,
        measured_cases=measured,
        provider=provider,
    )
    assert reopened == outcome.mapping.public_authority
    assert len(reopened.cases) == 6
    assert provider.managed_resources_absent()
