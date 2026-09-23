from __future__ import annotations

import ast
import asyncio
import json
import shutil
from copy import deepcopy
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import JsonValue, ValidationError

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import CampaignManifest, ToolRequest
from pajin.runtime.store import RunStore, load_verified_run_snapshot
from pajin.web_assessment.analysis_capacity_v2 import (
    WebAnalysisLiveModelCleanupOnlyResult,
    WebAnalysisLiveModelMaterializationAttestation,
    WebAnalysisLiveModelProviderRouteAttestation,
    WebAnalysisLiveModelResourceAbsenceProof,
)
from pajin.web_assessment.analysis_compact_live_transport import (
    expected_compact_web_analysis_provider_worker_context,
    expected_compact_web_analysis_transport_job_metadata,
    prepare_compact_web_analysis_transport_job,
)
from pajin.web_assessment.analysis_live_claim_journal import (
    VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate,
    WebAnalysisLiveClaimJournal,
    WebAnalysisLiveClaimJournalError,
    WebAnalysisLiveClaimPendingOutcome,
    WebAnalysisLiveClaimTerminalDisposition,
    build_web_analysis_live_claim_binding,
)
from pajin.web_assessment.analysis_skill_compact_live_receipts import (
    CompactSkillBoundWebAnalysisCleanupResult,
    CompactSkillBoundWebAnalysisDispatchObservation,
    CompactSkillBoundWebAnalysisTerminalIndex,
    CompactSkillBoundWebAnalysisTerminalReceipt,
    CompactSkillBoundWebAnalysisTerminalReceiptError,
    CompactSkillBoundWebAnalysisTransportBinding,
    compact_skill_bound_web_analysis_lease_id,
    compact_skill_bound_web_analysis_terminal_run_id,
    compact_skill_bound_web_analysis_terminal_run_path,
    load_verified_compact_skill_bound_web_analysis_pending_terminal_publication,
    load_verified_compact_skill_bound_web_analysis_terminal_publication_candidate,
    load_verified_compact_skill_bound_web_analysis_terminal_run,
    publish_compact_skill_bound_web_analysis_terminal_run,
)
from pajin.web_assessment.analysis_skill_invocation import (
    compile_skill_bound_web_analysis_proposal,
)
from pajin.web_assessment.analysis_skill_receipts import (
    SkillBoundWebAnalysisInvocationReceipt,
)
from pajin.web_assessment.analysis_skill_runtime import (
    SkillBoundWebAnalysisRuntimeError,
    load_verified_skill_bound_web_analysis_invocation,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportCleanupProof,
)
from tests.test_web_analysis_live_authorization_v2 import (
    _signed,
    _statement,
)
from tests.test_web_analysis_live_authorization_v2 import (
    _verify as verify_authorization,
)
from tests.test_web_analysis_skill_invocation import _successor_draft
from tests.test_web_analysis_skill_live_invocation import _admission_anchors
from tests.test_web_analysis_skill_runtime import (
    _EXPECTED_EXTERNAL_NETWORK,
)
from tests.test_web_analysis_skill_runtime import (
    _build_case as _build_legacy_case,
)
from tests.test_web_analysis_skill_runtime import (
    _invoke as _invoke_legacy_runtime,
)
from tests.test_web_analysis_skill_runtime import (
    _runtime as _legacy_runtime,
)
from tests.test_web_analysis_skill_runtime import (
    _successor_content as _legacy_successor_content,
)

PROJECT_ROOT = Path(__file__).parents[1]
pytest_plugins = ("tests.test_web_analysis_live_authorization_v2",)


class _MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _sha(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture(scope="module")  # type: ignore[untyped-decorator]
def authorization_context(authorization_v2_context: SimpleNamespace) -> SimpleNamespace:
    return authorization_v2_context


def _cleanup(
    *,
    claim_store_id: str,
    claim_digest: str,
    pending_claim_state_digest: str,
    dispatch_observation_digest: str,
    live_attestation_digest: str | None,
    provider_route_attestation_digest: str | None = None,
    owner: str,
    runtime_name: str,
    seed_name: str,
    volume_name: str,
    network_name: str,
    execution_id: str,
    transport_pin_digest: str,
    revoked_lease_ids: tuple[str, ...] = (),
) -> CompactSkillBoundWebAnalysisCleanupResult:
    absence = WebAnalysisLiveModelResourceAbsenceProof(
        resourceOwner=owner,
        runtimeContainerName=runtime_name,
        seedContainerName=seed_name,
        volumeName=volume_name,
        networkName=network_name,
        exactNameAbsenceVerified=True,
        ownerLabelAbsenceVerified=True,
        matchingContainerCount=0,
        matchingVolumeCount=0,
        matchingNetworkCount=0,
    )
    model_cleanup = WebAnalysisLiveModelCleanupOnlyResult(
        resourceOwner=owner,
        runtimeContainerName=runtime_name,
        seedContainerName=seed_name,
        volumeName=volume_name,
        networkName=network_name,
        removedResources=(),
        alreadyAbsentResources=(
            "runtime-container",
            "seed-container",
            "model-volume",
            "network",
        ),
        presentResourceOwnershipVerified=True,
        cleanupOnly=True,
        absenceProofDigest=absence.proof_digest,
    )
    transport_cleanup = WebAnalysisTransportCleanupProof(
        executionId=execution_id,
        transportPinDigest=transport_pin_digest,
        externalNetwork=network_name,
        observedResources=(),
    )
    return CompactSkillBoundWebAnalysisCleanupResult(
        claimStoreId=claim_store_id,
        claimDigest=claim_digest,
        pendingClaimStateDigest=pending_claim_state_digest,
        dispatchObservationDigest=dispatch_observation_digest,
        liveAttestationDigest=live_attestation_digest,
        providerRouteAttestationDigest=provider_route_attestation_digest,
        modelCleanup=model_cleanup,
        modelAbsence=absence,
        transportCleanup=transport_cleanup,
        revokedLeaseIds=revoked_lease_ids,
        credentialLeasesRevoked=True,
        allOwnedResourcesRemovedOrAbsent=True,
        aggregateAbsenceVerified=True,
    )


def _make_failure_receipt(
    context: SimpleNamespace,
    tmp_path: Path,
    *,
    lease_ids: tuple[str, ...] | None = (),
) -> SimpleNamespace:
    bundle = _signed(context, _statement(context))
    initial_auth = verify_authorization(context, bundle)
    binding = build_web_analysis_live_claim_binding(
        admission=context.admission,
        authorization=initial_auth.coordinate,
    )
    clock = _MutableClock(initial_auth.evaluated_at + timedelta(seconds=10))
    journal = WebAnalysisLiveClaimJournal(
        tmp_path / "claim.sqlite3", clock=clock, allow_create=True
    )
    reserved = journal.reserve_with_gate_d_context(
        binding,
        initial_authorization_verification_digest=initial_auth.verification_digest,
        initial_authorization_evaluated_at=initial_auth.evaluated_at,
        initial_authorization_expires_at=initial_auth.expires_at,
    )
    started = journal.begin_live(reserved)
    pending = journal.mark_pending_cleanup(
        started,
        outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
    )
    resources = binding.resources
    execution_id = f"exec_{resources.resource_owner}"
    registration = context.live_request.provider_registration
    chat = context.live_request.chat_request
    tool_request = ToolRequest(
        request_id=f"tool_{resources.resource_owner}",
        agent_id="web-analysis-compact-live",
        tool_id=f"provider.{registration.provider_id}.chat",
        target=str(registration.endpoint),
        method="POST",
        arguments=chat.model_dump(mode="python", by_alias=True),
    )
    if lease_ids is None:
        job = prepare_compact_web_analysis_transport_job(
            tool_request,
            capacity_pin=context.capacity_pin,
            registration=registration,
            live_request=context.live_request,
            lineage_transport_pin=context.transport_pin,
            runtime_pin=context.compact_runtime,
            transport_pin=context.compact_transport,
            expected_capacity_pin_digest=context.capacity_pin.pin_digest,
            expected_lineage_transport_pin_digest=context.transport_pin.pin_digest,
            expected_runtime_pin_digest=context.compact_runtime.pin_digest,
            expected_transport_pin_digest=context.compact_transport.pin_digest,
            execution_id=execution_id,
        )
        assert len(job.secret_requests) == 1
        request = job.secret_requests[0]
        lease_ids = (
            compact_skill_bound_web_analysis_lease_id(
                claim_digest=binding.claim_digest,
                secret_ref=request.secret_ref,
                binding=request.binding,
            ),
        )
    worker_context = expected_compact_web_analysis_provider_worker_context(
        context.compact_runtime,
        context.compact_transport,
        capacity_pin=context.capacity_pin,
        lineage_transport_pin=context.transport_pin,
        expected_capacity_pin_digest=context.capacity_pin.pin_digest,
        expected_lineage_transport_pin_digest=context.transport_pin.pin_digest,
        expected_runtime_pin_digest=context.compact_runtime.pin_digest,
        expected_transport_pin_digest=context.compact_transport.pin_digest,
        live_request=context.live_request,
        external_network=resources.network_name,
        claim_digest=binding.claim_digest,
        execution_id=execution_id,
    )
    job_metadata = expected_compact_web_analysis_transport_job_metadata(
        tool_request,
        capacity_pin=context.capacity_pin,
        registration=registration,
        live_request=context.live_request,
        lineage_transport_pin=context.transport_pin,
        runtime_pin=context.compact_runtime,
        transport_pin=context.compact_transport,
        expected_capacity_pin_digest=context.capacity_pin.pin_digest,
        expected_lineage_transport_pin_digest=context.transport_pin.pin_digest,
        expected_runtime_pin_digest=context.compact_runtime.pin_digest,
        expected_transport_pin_digest=context.compact_transport.pin_digest,
        execution_id=execution_id,
        lease_ids=list(lease_ids),
    )
    transport_binding = CompactSkillBoundWebAnalysisTransportBinding(
        liveRequest=context.live_request,
        capacityPin=context.capacity_pin,
        lineageTransportPin=context.transport_pin,
        compactRuntimePin=context.compact_runtime,
        compactRuntimePinDigest=context.compact_runtime.pin_digest,
        toolRequest=tool_request,
        providerRegistration=registration,
        compactTransportPin=context.compact_transport,
        compactTransportPinDigest=context.compact_transport.pin_digest,
        liveClaimDigest=binding.claim_digest,
        transportExecutionId=execution_id,
        externalNetwork=resources.network_name,
        leaseIds=lease_ids,
        workerContext=worker_context,
        workerContextDigest="",
        jobMetadata=cast(dict[str, JsonValue], job_metadata),
        jobMetadataDigest="",
        secretMaterialEmbedded=False,
        externalEgressAuthority=False,
    )
    observation = CompactSkillBoundWebAnalysisDispatchObservation(
        providerId=registration.provider_id,
        modelId=registration.model,
        transportExecutionId=execution_id,
        transportBindingDigest=transport_binding.binding_digest,
        transportWorkerContextDigest=transport_binding.worker_context_digest,
        transportJobMetadataDigest=transport_binding.job_metadata_digest,
        providerRegistrationDigest=context.live_request.provider_registration_digest,
        providerChatRequestDigest=context.live_request.chat_request_digest,
        pendingOutcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
        dispatchCount=0,
        responseEvidenceAvailable=False,
        failureDigest=_sha("materialization-failure"),
    )
    cleanup = _cleanup(
        claim_store_id=journal.store_id,
        claim_digest=binding.claim_digest,
        pending_claim_state_digest=pending.state_digest,
        dispatch_observation_digest=observation.observation_digest,
        live_attestation_digest=None,
        owner=resources.resource_owner,
        runtime_name=resources.runtime_container_name,
        seed_name=resources.seed_container_name,
        volume_name=resources.volume_name,
        network_name=resources.network_name,
        execution_id=execution_id,
        transport_pin_digest=context.compact_transport.pin_digest,
        revoked_lease_ids=lease_ids,
    )
    gate_d_context = journal.inspect_gate_d_context(binding.claim_id)
    assert gate_d_context is not None
    run_id = compact_skill_bound_web_analysis_terminal_run_id(pending)
    receipt = CompactSkillBoundWebAnalysisTerminalReceipt(
        terminalRunId=run_id,
        admission=context.admission,
        capacityPin=context.capacity_pin,
        compactRuntimePin=context.compact_runtime,
        compactTransportPin=context.compact_transport,
        signedAuthorization=bundle,
        initialAuthorizationVerification=initial_auth,
        preDispatchAuthorizationVerification=None,
        claimStoreId=journal.store_id,
        gateDContextDigest=gate_d_context.context_digest,
        pendingClaim=pending,
        liveMaterializationAttestation=None,
        providerRegistration=registration,
        providerChatRequest=chat,
        transportBinding=transport_binding,
        transportExecutionId=execution_id,
        dispatchObservation=observation,
        cleanupResult=cleanup,
        draft=None,
        compiledProposal=None,
        intendedTerminalDisposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        failureStage="materialization",
        failureDigest=_sha("materialization-failure"),
        cleanupBound=True,
        terminalJournalCrossLinkRequired=True,
        targetRequestAuthority=False,
        toolRequestAuthority=False,
        capabilityAuthority=False,
        permitAuthority=False,
        findingAuthority=False,
        graphAdmissionAuthority=False,
        reportAuthority=False,
        deliveryAuthority=False,
        retryAuthority=False,
        automaticRedispatchAuthority=False,
    )
    return SimpleNamespace(
        bundle=bundle,
        journal=journal,
        pending=pending,
        receipt=receipt,
        cleanup=cleanup,
        gate_d_context=gate_d_context,
    )


def _live_attestation(
    context: SimpleNamespace,
    *,
    owner: str,
    runtime_name: str,
    volume_name: str,
    network_name: str,
) -> WebAnalysisLiveModelMaterializationAttestation:
    pin = context.capacity_pin
    return WebAnalysisLiveModelMaterializationAttestation(
        capacityRunId=context.admission.capacity_run_id,
        capacityRootDigest=context.admission.capacity_run_root_digest,
        capacityPinDigest=pin.pin_digest,
        capacityProofDigest=context.admission.capacity_proof_digest,
        capacityMaterializationAttestationDigest=(
            context.admission.model_materialization_attestation_digest
        ),
        modelPinDigest=pin.model_pin_digest,
        modelSha256=pin.model_sha256,
        modelSizeBytes=pin.model_size_bytes,
        descriptorIdentityDigest=_sha("live-descriptor-identity"),
        descriptorIdentityStable=True,
        stagedModelSha256=pin.model_sha256,
        stagedModelSizeBytes=pin.model_size_bytes,
        stagedModelUid=10001,
        stagedModelGid=10001,
        stagedModelMode="0400",
        mountedModelSha256=pin.model_sha256,
        mountedModelSizeBytes=pin.model_size_bytes,
        mountedModelUid=10001,
        mountedModelGid=10001,
        mountedModelMode="0400",
        modelImage=pin.tokenizer_image,
        modelImageId=pin.tokenizer_image_id,
        modelPlatform=pin.model_platform,
        modelPlatformManifest=pin.model_platform_manifest,
        resourceOwner=owner,
        volumeName=volume_name,
        runtimeContainerName=runtime_name,
        runtimeContainerId="a" * 64,
        networkName=network_name,
        networkId="b" * 64,
        mountType="volume",
        mountDestination="/models",
        mountReadOnly=True,
        runtimeUser="10001:10001",
        runtimeUserReadVerified=True,
        internalNetwork=True,
        publishedPorts=0,
        livePort=8080,
        ownershipVerified=True,
        attestedBeforeModelDispatch=True,
        cleanupRequired=True,
    )


def _provider_route_attestation(
    context: SimpleNamespace,
    *,
    claim_digest: str,
    attestation: WebAnalysisLiveModelMaterializationAttestation,
) -> WebAnalysisLiveModelProviderRouteAttestation:
    return WebAnalysisLiveModelProviderRouteAttestation(
        claimDigest=claim_digest,
        resourceOwner=attestation.resource_owner,
        liveMaterializationAttestationDigest=attestation.attestation_digest,
        runtimeContainerName=attestation.runtime_container_name,
        runtimeContainerId=attestation.runtime_container_id,
        networkName=attestation.network_name,
        networkId=attestation.network_id,
        providerRegistrationDigest=context.live_request.provider_registration_digest,
        providerEndpoint=str(context.live_request.provider_registration.endpoint),
        providerEndpointScheme="http",
        providerEndpointHost="host.docker.internal",
        providerEndpointPort=8080,
        providerEndpointPath="/v1/chat/completions",
        providerNetworkAlias="host.docker.internal",
        livePort=8080,
        providerAliasExact=True,
        networkMembersExact=True,
        attestedBeforeProviderDispatch=True,
    )


def _make_success_receipt(
    context: SimpleNamespace,
    tmp_path: Path,
    *,
    lease_ids: tuple[str, ...] | None = None,
) -> SimpleNamespace:
    base = _make_failure_receipt(context, tmp_path / "base", lease_ids=lease_ids)
    binding = base.pending.binding
    initial_auth = base.receipt.initial_authorization_verification
    clock = _MutableClock(initial_auth.evaluated_at + timedelta(seconds=10))
    journal = WebAnalysisLiveClaimJournal(
        tmp_path / "success.sqlite3", clock=clock, allow_create=True
    )
    reserved = journal.reserve_with_gate_d_context(
        binding,
        initial_authorization_verification_digest=initial_auth.verification_digest,
        initial_authorization_evaluated_at=initial_auth.evaluated_at,
        initial_authorization_expires_at=initial_auth.expires_at,
    )
    started = journal.begin_live(reserved)
    resources = binding.resources
    attestation = _live_attestation(
        context,
        owner=resources.resource_owner,
        runtime_name=resources.runtime_container_name,
        volume_name=resources.volume_name,
        network_name=resources.network_name,
    )
    provider_route_attestation = _provider_route_attestation(
        context,
        claim_digest=binding.claim_digest,
        attestation=attestation,
    )
    draft = _successor_draft(context.skill_run)
    proposal = compile_skill_bound_web_analysis_proposal(
        source=context.source,
        skill_run=context.skill_run,
        draft=draft,
        transport_pin=context.transport_pin,
        expected_source_run_id=context.source.verification.run_id,
        expected_source_root_digest=context.source.verification.root_digest,
        expected_skill_run_id=context.skill_run.verification.run_id,
        expected_skill_root_digest=context.skill_run.verification.root_digest,
        expected_registry_ref=context.skill_run.index.registry,
        expected_policy_digest=context.skill_run.index.selection_policy_digest,
        expected_transport_pin_digest=context.transport_pin.pin_digest,
    )
    response = canonical_json_bytes(
        draft.model_dump(mode="json", by_alias=True),
        label="test compact live retained response draft",
    )
    transport_binding = base.receipt.transport_binding
    clock.value = initial_auth.evaluated_at + timedelta(seconds=11)
    pre_dispatch_auth = verify_authorization(
        context,
        base.bundle,
        clock=clock.value,
    )
    started = journal.record_gate_d_pre_dispatch_context(
        started,
        pre_dispatch_authorization_verification_digest=(pre_dispatch_auth.verification_digest),
        pre_dispatch_authorization_evaluated_at=pre_dispatch_auth.evaluated_at,
        pre_dispatch_authorization_expires_at=pre_dispatch_auth.expires_at,
        provider_route_attestation_digest=provider_route_attestation.attestation_digest,
        transport_execution_id=transport_binding.transport_execution_id,
        lease_ids=transport_binding.lease_ids,
        worker_context_digest=transport_binding.worker_context_digest,
        job_metadata_digest=transport_binding.job_metadata_digest,
        transport_binding_digest=transport_binding.binding_digest,
    )
    clock.value = initial_auth.evaluated_at + timedelta(seconds=12)
    dispatch_started = journal.mark_dispatch_started(started)
    clock.value = initial_auth.evaluated_at + timedelta(seconds=13)
    pending = journal.mark_pending_cleanup(
        dispatch_started,
        outcome=WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED,
    )
    observation = CompactSkillBoundWebAnalysisDispatchObservation(
        providerId=base.receipt.provider_registration.provider_id,
        modelId=base.receipt.provider_registration.model,
        transportExecutionId=base.receipt.transport_execution_id,
        transportBindingDigest=transport_binding.binding_digest,
        transportWorkerContextDigest=transport_binding.worker_context_digest,
        transportJobMetadataDigest=transport_binding.job_metadata_digest,
        providerRegistrationDigest=context.live_request.provider_registration_digest,
        providerChatRequestDigest=context.live_request.chat_request_digest,
        pendingOutcome=WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED,
        dispatchCount=1,
        responseSha256=sha256(response).hexdigest(),
        responseBytes=len(response),
        responseEvidenceAvailable=True,
        failureDigest=None,
    )
    cleanup = _cleanup(
        claim_store_id=journal.store_id,
        claim_digest=binding.claim_digest,
        pending_claim_state_digest=pending.state_digest,
        dispatch_observation_digest=observation.observation_digest,
        live_attestation_digest=attestation.attestation_digest,
        provider_route_attestation_digest=provider_route_attestation.attestation_digest,
        owner=resources.resource_owner,
        runtime_name=resources.runtime_container_name,
        seed_name=resources.seed_container_name,
        volume_name=resources.volume_name,
        network_name=resources.network_name,
        execution_id=transport_binding.transport_execution_id,
        transport_pin_digest=context.compact_transport.pin_digest,
        revoked_lease_ids=transport_binding.lease_ids,
    )
    gate_d_context = journal.inspect_gate_d_context(binding.claim_id)
    assert gate_d_context is not None
    receipt = CompactSkillBoundWebAnalysisTerminalReceipt(
        terminalRunId=compact_skill_bound_web_analysis_terminal_run_id(pending),
        admission=context.admission,
        capacityPin=context.capacity_pin,
        compactRuntimePin=context.compact_runtime,
        compactTransportPin=context.compact_transport,
        signedAuthorization=base.bundle,
        initialAuthorizationVerification=initial_auth,
        preDispatchAuthorizationVerification=pre_dispatch_auth,
        claimStoreId=journal.store_id,
        gateDContextDigest=gate_d_context.context_digest,
        pendingClaim=pending,
        liveMaterializationAttestation=attestation,
        providerRouteAttestation=provider_route_attestation,
        providerRegistration=base.receipt.provider_registration,
        providerChatRequest=base.receipt.provider_chat_request,
        transportBinding=transport_binding,
        transportExecutionId=base.receipt.transport_execution_id,
        dispatchObservation=observation,
        cleanupResult=cleanup,
        draft=draft,
        compiledProposal=proposal,
        intendedTerminalDisposition=WebAnalysisLiveClaimTerminalDisposition.SUCCESS,
        failureStage=None,
        failureDigest=None,
        cleanupBound=True,
        terminalJournalCrossLinkRequired=True,
        targetRequestAuthority=False,
        toolRequestAuthority=False,
        capabilityAuthority=False,
        permitAuthority=False,
        findingAuthority=False,
        graphAdmissionAuthority=False,
        reportAuthority=False,
        deliveryAuthority=False,
        retryAuthority=False,
        automaticRedispatchAuthority=False,
    )
    return SimpleNamespace(
        bundle=base.bundle,
        journal=journal,
        pending=pending,
        receipt=receipt,
        cleanup=cleanup,
        gate_d_context=gate_d_context,
        attestation=attestation,
        provider_route_attestation=provider_route_attestation,
        draft=draft,
        proposal=proposal,
    )


def _make_dispatched_non_success_receipt(
    context: SimpleNamespace,
    tmp_path: Path,
    *,
    outcome: WebAnalysisLiveClaimPendingOutcome,
    failure_stage: str,
) -> SimpleNamespace:
    template = _make_success_receipt(context, tmp_path / "template")
    binding = template.pending.binding
    initial_auth = template.receipt.initial_authorization_verification
    pre_dispatch_auth = template.receipt.pre_dispatch_authorization_verification
    assert pre_dispatch_auth is not None
    clock = _MutableClock(initial_auth.evaluated_at + timedelta(seconds=10))
    journal = WebAnalysisLiveClaimJournal(
        tmp_path / "non-success.sqlite3",
        clock=clock,
        allow_create=True,
    )
    reserved = journal.reserve_with_gate_d_context(
        binding,
        initial_authorization_verification_digest=initial_auth.verification_digest,
        initial_authorization_evaluated_at=initial_auth.evaluated_at,
        initial_authorization_expires_at=initial_auth.expires_at,
    )
    started = journal.begin_live(reserved)
    clock.value = pre_dispatch_auth.evaluated_at
    transport = template.receipt.transport_binding
    started = journal.record_gate_d_pre_dispatch_context(
        started,
        pre_dispatch_authorization_verification_digest=(pre_dispatch_auth.verification_digest),
        pre_dispatch_authorization_evaluated_at=pre_dispatch_auth.evaluated_at,
        pre_dispatch_authorization_expires_at=pre_dispatch_auth.expires_at,
        provider_route_attestation_digest=(template.provider_route_attestation.attestation_digest),
        transport_execution_id=transport.transport_execution_id,
        lease_ids=transport.lease_ids,
        worker_context_digest=transport.worker_context_digest,
        job_metadata_digest=transport.job_metadata_digest,
        transport_binding_digest=transport.binding_digest,
    )
    clock.value = pre_dispatch_auth.evaluated_at + timedelta(seconds=1)
    dispatch_started = journal.mark_dispatch_started(started)
    clock.value = pre_dispatch_auth.evaluated_at + timedelta(seconds=2)
    pending = journal.mark_pending_cleanup(dispatch_started, outcome=outcome)
    failure_digest = _sha(f"{outcome.value}:{failure_stage}")
    observation = CompactSkillBoundWebAnalysisDispatchObservation(
        providerId=template.receipt.provider_registration.provider_id,
        modelId=template.receipt.provider_registration.model,
        transportExecutionId=transport.transport_execution_id,
        transportBindingDigest=transport.binding_digest,
        transportWorkerContextDigest=transport.worker_context_digest,
        transportJobMetadataDigest=transport.job_metadata_digest,
        providerRegistrationDigest=context.live_request.provider_registration_digest,
        providerChatRequestDigest=context.live_request.chat_request_digest,
        pendingOutcome=outcome,
        dispatchCount=1,
        responseEvidenceAvailable=False,
        failureDigest=failure_digest,
    )
    resources = binding.resources
    cleanup = _cleanup(
        claim_store_id=journal.store_id,
        claim_digest=binding.claim_digest,
        pending_claim_state_digest=pending.state_digest,
        dispatch_observation_digest=observation.observation_digest,
        live_attestation_digest=template.attestation.attestation_digest,
        provider_route_attestation_digest=(template.provider_route_attestation.attestation_digest),
        owner=resources.resource_owner,
        runtime_name=resources.runtime_container_name,
        seed_name=resources.seed_container_name,
        volume_name=resources.volume_name,
        network_name=resources.network_name,
        execution_id=transport.transport_execution_id,
        transport_pin_digest=context.compact_transport.pin_digest,
        revoked_lease_ids=transport.lease_ids,
    )
    gate_d_context = journal.inspect_gate_d_context(binding.claim_id)
    assert gate_d_context is not None
    disposition = (
        WebAnalysisLiveClaimTerminalDisposition.FAILURE
        if outcome is WebAnalysisLiveClaimPendingOutcome.FAILURE_OBSERVED
        else WebAnalysisLiveClaimTerminalDisposition.ABANDONED
    )
    receipt_wire = template.receipt.model_dump(mode="python", by_alias=True)
    receipt_wire.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "terminalRunId": compact_skill_bound_web_analysis_terminal_run_id(pending),
            "claimStoreId": journal.store_id,
            "gateDContextDigest": gate_d_context.context_digest,
            "pendingClaim": pending.model_dump(mode="python", by_alias=True),
            "dispatchObservation": observation.model_dump(mode="python", by_alias=True),
            "cleanupResult": cleanup.model_dump(mode="python", by_alias=True),
            "draft": None,
            "compiledProposal": None,
            "intendedTerminalDisposition": disposition,
            "failureStage": failure_stage,
            "failureDigest": failure_digest,
        }
    )
    receipt = CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(receipt_wire)
    return SimpleNamespace(
        bundle=template.bundle,
        journal=journal,
        pending=pending,
        receipt=receipt,
        cleanup=cleanup,
        gate_d_context=gate_d_context,
        attestation=template.attestation,
        provider_route_attestation=template.provider_route_attestation,
    )


def _load(
    context: SimpleNamespace,
    built: SimpleNamespace,
    publication: Any,
    *,
    pending: bool = False,
    candidate: bool = False,
    run_path: Path | None = None,
    overrides: dict[str, object] | None = None,
) -> Any:
    trust_anchor = context.trust_anchor
    values: dict[str, object] = {
        "expected_output_root": publication.run_path.parents[1],
        "expected_run_id": publication.run_id,
        "expected_root_digest": publication.root_digest,
        "expected_receipt_digest": built.receipt.receipt_digest,
        "expected_claim_digest": built.pending.binding.claim_digest,
        "expected_live_attestation_digest": (
            None if not hasattr(built, "attestation") else built.attestation.attestation_digest
        ),
        "source": context.source,
        "skill_run": context.skill_run,
        "capacity_run": context.capacity,
        "preparation_run": context.preparation,
        "admission": context.admission,
        "transport_pin": context.transport_pin,
        "compact_runtime_pin": context.compact_runtime,
        "compact_transport_pin": context.compact_transport,
        "trust_anchor": trust_anchor,
        "expected_trust_anchor_digest": trust_anchor.digest,
        "journal": built.journal,
        "expected_claim_store_id": built.journal.store_id,
        "expected_compact_runtime_pin_digest": context.compact_runtime.pin_digest,
        "expected_compact_transport_pin_digest": context.compact_transport.pin_digest,
    }
    values.update(
        _admission_anchors(
            context.source,
            context.skill_run,
            context.capacity,
            context.preparation,
        )
    )
    if overrides is not None:
        values.update(overrides)
    if candidate:
        values.pop("expected_root_digest")
        loader = load_verified_compact_skill_bound_web_analysis_terminal_publication_candidate
    elif pending:
        loader = load_verified_compact_skill_bound_web_analysis_pending_terminal_publication
    else:
        loader = load_verified_compact_skill_bound_web_analysis_terminal_run
    return cast(Any, loader)(run_path or publication.run_path, **values)


def _publish_and_anchor(
    context: SimpleNamespace,
    built: SimpleNamespace,
    output_root: Path,
    *,
    receipt: CompactSkillBoundWebAnalysisTerminalReceipt | None = None,
    draft: object | None = None,
    proposal: object | None = None,
) -> Any:
    exact_receipt = built.receipt if receipt is None else receipt
    run_path = compact_skill_bound_web_analysis_terminal_run_path(output_root, built.pending)
    intent = built.journal.record_terminal_publication_intent(
        built.pending,
        output_root=output_root,
        run_path=run_path,
        run_id=exact_receipt.terminal_run_id,
        receipt_digest=exact_receipt.receipt_digest,
        cleanup_result_digest=exact_receipt.cleanup_result.cleanup_digest,
        resource_absence_digest=exact_receipt.cleanup_result.resource_absence_digest,
        disposition=exact_receipt.intended_terminal_disposition,
        live_attestation_digest=(
            None
            if exact_receipt.live_materialization_attestation is None
            else exact_receipt.live_materialization_attestation.attestation_digest
        ),
    )
    publication = publish_compact_skill_bound_web_analysis_terminal_run(
        output_root,
        receipt=exact_receipt,
        signed_authorization=built.bundle,
        draft=cast(Any, draft),
        proposal=cast(Any, proposal),
    )
    candidate = _load(
        context,
        built,
        publication,
        candidate=True,
        overrides={"expected_receipt_digest": exact_receipt.receipt_digest},
    )
    assert candidate.verified_candidate is not None
    anchored = built.journal.anchor_terminal_publication(
        built.pending,
        intent,
        candidate.verified_candidate,
    )
    assert anchored.root_digest == publication.root_digest
    return publication


def test_cleanup_bound_failure_receipt_round_trips_strictly(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)
    publication = _publish_and_anchor(
        authorization_context,
        built,
        tmp_path / "terminal",
    )
    terminal = built.journal.finalize_terminal(
        built.pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        terminal_receipt_digest=built.receipt.receipt_digest,
    )

    loaded = _load(authorization_context, built, publication)

    assert loaded.receipt == built.receipt
    assert loaded.terminal_claim == terminal
    assert loaded.proposal is None
    assert loaded.receipt.pre_dispatch_authorization_verification is None
    assert loaded.receipt.live_materialization_attestation is None
    assert loaded.target_request_authority is False
    assert loaded.automatic_redispatch_authority is False


def test_full_success_receipt_round_trips_with_response_and_proposal(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_success_receipt(authorization_context, tmp_path)
    publication = _publish_and_anchor(
        authorization_context,
        built,
        tmp_path / "terminal",
        draft=built.draft,
        proposal=built.proposal,
    )
    terminal = built.journal.finalize_terminal(
        built.pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.SUCCESS,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        terminal_receipt_digest=built.receipt.receipt_digest,
    )

    loaded = _load(authorization_context, built, publication)

    assert loaded.receipt == built.receipt
    assert loaded.terminal_claim == terminal
    assert loaded.draft == built.draft
    assert loaded.proposal == built.proposal
    assert loaded.receipt.dispatch_observation.response_evidence_available is True


def test_existing_seal_is_reloaded_and_finalized_without_second_publication(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_success_receipt(authorization_context, tmp_path)
    output_root = tmp_path / "terminal"
    expected_path = compact_skill_bound_web_analysis_terminal_run_path(output_root, built.pending)
    publication = _publish_and_anchor(
        authorization_context,
        built,
        output_root,
        draft=built.draft,
        proposal=built.proposal,
    )
    assert publication.run_path == expected_path

    pending = _load(
        authorization_context,
        built,
        publication,
        pending=True,
    )
    assert pending.run_path == publication.run_path
    assert pending.run_id == publication.run_id
    assert pending.root_digest == publication.root_digest
    assert pending.receipt_digest == built.receipt.receipt_digest
    assert pending.cleanup_result_digest == built.cleanup.cleanup_digest
    assert pending.resource_absence_digest == built.cleanup.resource_absence_digest
    assert pending.live_attestation_digest == built.attestation.attestation_digest
    assert pending.pending_claim == built.pending
    assert pending.verified_candidate is None
    assert pending.proposal_exposed is False

    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="publication failed closed",
    ):
        publish_compact_skill_bound_web_analysis_terminal_run(
            output_root,
            receipt=built.receipt,
            signed_authorization=built.bundle,
            draft=built.draft,
            proposal=built.proposal,
        )

    built.journal.finalize_terminal(
        pending.pending_claim,
        disposition=pending.intended_terminal_disposition,
        cleanup_result_digest=pending.cleanup_result_digest,
        resource_absence_digest=pending.resource_absence_digest,
        terminal_receipt_digest=pending.receipt_digest,
    )
    terminal = _load(authorization_context, built, publication)
    assert terminal.run_path == pending.run_path
    assert terminal.verification.root_digest == pending.root_digest
    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="failed strict verification",
    ):
        _load(
            authorization_context,
            built,
            publication,
            pending=True,
        )


def test_publication_candidate_is_unconstructible_store_local_and_one_use(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    with pytest.raises(TypeError, match="strict loader"):
        VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate()

    built = _make_failure_receipt(authorization_context, tmp_path)
    output_root = tmp_path / "terminal"
    run_path = compact_skill_bound_web_analysis_terminal_run_path(output_root, built.pending)
    intent = built.journal.record_terminal_publication_intent(
        built.pending,
        output_root=output_root,
        run_path=run_path,
        run_id=built.receipt.terminal_run_id,
        receipt_digest=built.receipt.receipt_digest,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        disposition=built.receipt.intended_terminal_disposition,
        live_attestation_digest=None,
    )
    assert not hasattr(
        built.journal,
        "_issue_verified_terminal_publication_candidate_from_strict_loader",
    )
    forged = object.__new__(VerifiedWebAnalysisLiveClaimTerminalPublicationCandidate)
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        built.journal.anchor_terminal_publication(
            built.pending,
            intent,
            forged,
        )
    publication = publish_compact_skill_bound_web_analysis_terminal_run(
        output_root,
        receipt=built.receipt,
        signed_authorization=built.bundle,
        draft=None,
        proposal=None,
    )
    candidate = _load(
        authorization_context,
        built,
        publication,
        candidate=True,
    )
    assert candidate.verified_candidate is not None
    assert candidate.verified_candidate.root_digest == publication.root_digest
    foreign_journal = WebAnalysisLiveClaimJournal(
        tmp_path / "foreign-claim.sqlite3",
        allow_create=True,
    )
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        foreign_journal.anchor_terminal_publication(
            built.pending,
            intent,
            candidate.verified_candidate,
        )
    anchored = built.journal.anchor_terminal_publication(
        built.pending,
        intent,
        candidate.verified_candidate,
    )
    assert anchored.root_digest == publication.root_digest
    with pytest.raises(WebAnalysisLiveClaimJournalError, match="foreign or consumed"):
        built.journal.anchor_terminal_publication(
            built.pending,
            intent,
            candidate.verified_candidate,
        )


def test_loader_rejects_publication_row_change_across_artifact_io(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)
    publication = _publish_and_anchor(
        authorization_context,
        built,
        tmp_path / "terminal",
    )
    terminal = built.journal.finalize_terminal(
        built.pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        terminal_receipt_digest=built.receipt.receipt_digest,
    )
    durable = built.journal.inspect_terminal_publication(terminal.binding.claim_id)
    assert durable is not None
    substituted = durable.model_copy(update={"intent_digest": "0" * 64})
    inspections = 0

    def changing_publication(_claim_id: str) -> Any:
        nonlocal inspections
        inspections += 1
        return durable if inspections == 1 else substituted

    monkeypatch.setattr(
        built.journal,
        "inspect_terminal_publication",
        changing_publication,
    )
    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="failed strict verification",
    ):
        _load(authorization_context, built, publication)
    assert inspections == 2


def test_wrong_self_sealed_candidate_never_anchors_publication_intent(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path / "target-claim")
    output_root = tmp_path / "target-terminal"
    target_path = compact_skill_bound_web_analysis_terminal_run_path(
        output_root,
        built.pending,
    )
    intent = built.journal.record_terminal_publication_intent(
        built.pending,
        output_root=output_root,
        run_path=target_path,
        run_id=built.receipt.terminal_run_id,
        receipt_digest=built.receipt.receipt_digest,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        disposition=built.receipt.intended_terminal_disposition,
        live_attestation_digest=None,
    )
    assert intent.root_digest is None

    foreign = _make_failure_receipt(authorization_context, tmp_path / "foreign-claim")
    foreign_publication = _publish_and_anchor(
        authorization_context,
        foreign,
        tmp_path / "foreign-terminal",
    )
    foreign_snapshot = load_verified_run_snapshot(
        foreign_publication.run_path,
        expected_run_id=foreign_publication.run_id,
    )
    store = RunStore.create(
        output_root,
        target_path.parent.name,
        run_id=built.receipt.terminal_run_id,
    )
    for event in foreign_snapshot.events:
        store.append_event(event.event_type, event.payload)
    for artifact in foreign_snapshot.seals[0].artifacts:
        store.write_bytes(
            artifact.path,
            (foreign_publication.run_path / artifact.path).read_bytes(),
        )
    seal = store.seal()
    wrong = SimpleNamespace(
        run_path=store.path,
        run_id=built.receipt.terminal_run_id,
        root_digest=seal.root_digest,
    )

    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="failed strict verification",
    ):
        _load(
            authorization_context,
            built,
            wrong,
            candidate=True,
        )
    durable = built.journal.inspect_terminal_publication(built.pending.binding.claim_id)
    assert durable == intent
    assert durable is not None and durable.root_digest is None
    assert built.pending.dispatch_count == 0


def test_pending_publication_loader_rejects_tampered_existing_seal(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)
    publication = _publish_and_anchor(
        authorization_context,
        built,
        tmp_path / "terminal",
    )
    (publication.run_path / "compact-live-terminal-index.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="failed strict verification",
    ):
        _load(
            authorization_context,
            built,
            publication,
            pending=True,
        )


def test_quiescent_recovery_abandons_observed_success_without_fabricating_proposal(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    successful = _make_success_receipt(authorization_context, tmp_path)
    failure_digest = _sha("quiescent-recovery-evidence-loss")
    observation_wire = successful.receipt.dispatch_observation.model_dump(
        mode="python", by_alias=True
    )
    observation_wire.update(
        {
            "observationDigest": "",
            "responseSha256": None,
            "responseBytes": 0,
            "responseEvidenceAvailable": False,
            "failureDigest": failure_digest,
        }
    )
    observation = CompactSkillBoundWebAnalysisDispatchObservation.model_validate(observation_wire)
    resources = successful.pending.binding.resources
    cleanup = _cleanup(
        claim_store_id=successful.journal.store_id,
        claim_digest=successful.pending.binding.claim_digest,
        pending_claim_state_digest=successful.pending.state_digest,
        dispatch_observation_digest=observation.observation_digest,
        live_attestation_digest=None,
        provider_route_attestation_digest=(
            successful.gate_d_context.provider_route_attestation_digest
        ),
        owner=resources.resource_owner,
        runtime_name=resources.runtime_container_name,
        seed_name=resources.seed_container_name,
        volume_name=resources.volume_name,
        network_name=resources.network_name,
        execution_id=successful.receipt.transport_execution_id,
        transport_pin_digest=successful.receipt.compact_transport_pin.pin_digest,
        revoked_lease_ids=successful.receipt.transport_binding.lease_ids,
    )
    receipt_wire = successful.receipt.model_dump(mode="python", by_alias=True)
    receipt_wire.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "liveMaterializationAttestation": None,
            "providerRouteAttestation": None,
            "dispatchObservation": observation_wire,
            "cleanupResult": cleanup.model_dump(mode="python", by_alias=True),
            "draft": None,
            "compiledProposal": None,
            "intendedTerminalDisposition": (WebAnalysisLiveClaimTerminalDisposition.ABANDONED),
            "failureStage": "quiescent-recovery",
            "failureDigest": failure_digest,
        }
    )
    receipt = CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(receipt_wire)
    wrong_stage_wire = deepcopy(receipt_wire)
    wrong_stage_wire.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "failureStage": "dispatch",
        }
    )
    with pytest.raises(ValidationError, match="failure stage differs"):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(wrong_stage_wire)
    built = SimpleNamespace(
        bundle=successful.bundle,
        journal=successful.journal,
        pending=successful.pending,
        receipt=receipt,
        cleanup=cleanup,
    )
    publication = _publish_and_anchor(
        authorization_context,
        built,
        tmp_path / "terminal",
        receipt=receipt,
    )
    built.journal.finalize_terminal(
        built.pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        terminal_receipt_digest=receipt.receipt_digest,
    )

    loaded = _load(authorization_context, built, publication)

    assert loaded.receipt.failure_stage == "quiescent-recovery"
    assert loaded.receipt.dispatch_observation.pending_outcome is (
        WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
    )
    assert loaded.receipt.dispatch_observation.response_evidence_available is False
    assert loaded.receipt.provider_route_attestation is None
    assert (
        loaded.receipt.cleanup_result.provider_route_attestation_digest
        == loaded.gate_d_context.provider_route_attestation_digest
        == successful.provider_route_attestation.attestation_digest
    )
    assert loaded.draft is None
    assert loaded.proposal is None


def test_dispatched_non_success_outcomes_have_one_canonical_disposition(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    cases = (
        (
            WebAnalysisLiveClaimPendingOutcome.FAILURE_OBSERVED,
            "response-validation",
            WebAnalysisLiveClaimTerminalDisposition.FAILURE,
        ),
        (
            WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN,
            "dispatch",
            WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        ),
    )
    for outcome, failure_stage, disposition in cases:
        case_root = tmp_path / outcome.value
        built = _make_dispatched_non_success_receipt(
            authorization_context,
            case_root,
            outcome=outcome,
            failure_stage=failure_stage,
        )
        publication = _publish_and_anchor(
            authorization_context,
            built,
            case_root / "terminal",
        )
        built.journal.finalize_terminal(
            built.pending,
            disposition=disposition,
            cleanup_result_digest=built.cleanup.cleanup_digest,
            resource_absence_digest=built.cleanup.resource_absence_digest,
            terminal_receipt_digest=built.receipt.receipt_digest,
        )
        loaded = _load(authorization_context, built, publication)
        assert loaded.receipt.intended_terminal_disposition is disposition

        wrong = (
            WebAnalysisLiveClaimTerminalDisposition.ABANDONED
            if disposition is WebAnalysisLiveClaimTerminalDisposition.FAILURE
            else WebAnalysisLiveClaimTerminalDisposition.FAILURE
        )
        wire = built.receipt.model_dump(mode="python", by_alias=True)
        wire.update(
            {
                "receiptId": "",
                "receiptDigest": "",
                "intendedTerminalDisposition": wrong,
            }
        )
        with pytest.raises(ValidationError, match="terminal disposition differs"):
            CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(wire)


def test_loader_rejects_noncanonical_or_unsealed_artifact_layout(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    for mutation in ("duplicate-key", "extra", "missing", "renamed", "symlink"):
        case_root = tmp_path / mutation
        built = _make_failure_receipt(authorization_context, case_root)
        publication = _publish_and_anchor(
            authorization_context,
            built,
            case_root / "terminal",
        )
        built.journal.finalize_terminal(
            built.pending,
            disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
            cleanup_result_digest=built.cleanup.cleanup_digest,
            resource_absence_digest=built.cleanup.resource_absence_digest,
            terminal_receipt_digest=built.receipt.receipt_digest,
        )
        receipt_path = publication.run_path / "compact-live-terminal-receipt.json"
        if mutation == "duplicate-key":
            receipt_path.write_bytes(b'{"apiVersion":"x","apiVersion":"y"}\n')
        elif mutation == "extra":
            (publication.run_path / "extra.json").write_text("{}\n", encoding="utf-8")
        elif mutation == "missing":
            receipt_path.unlink()
        elif mutation == "renamed":
            receipt_path.rename(publication.run_path / "renamed-receipt.json")
        else:
            receipt_path.unlink()
            receipt_path.symlink_to("proposal-draft.json")

        with pytest.raises(
            CompactSkillBoundWebAnalysisTerminalReceiptError,
            match="failed strict verification",
        ):
            _load(authorization_context, built, publication)


def test_terminal_journal_cross_link_is_mandatory(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)
    publication = _publish_and_anchor(
        authorization_context,
        built,
        tmp_path / "terminal",
    )
    with pytest.raises(
        WebAnalysisLiveClaimJournalError,
        match="anchored publication",
    ):
        built.journal.finalize_terminal(
            built.pending,
            disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
            cleanup_result_digest=built.cleanup.cleanup_digest,
            resource_absence_digest=built.cleanup.resource_absence_digest,
            terminal_receipt_digest=_sha("wrong-terminal-receipt"),
        )
    pending = _load(authorization_context, built, publication, pending=True)
    assert pending.pending_claim == built.pending


def test_loader_rejects_claim_journal_store_substitution(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)
    publication = _publish_and_anchor(
        authorization_context,
        built,
        tmp_path / "terminal",
    )
    built.journal.finalize_terminal(
        built.pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        terminal_receipt_digest=built.receipt.receipt_digest,
    )
    foreign = WebAnalysisLiveClaimJournal(tmp_path / "foreign-claim.sqlite3", allow_create=True)

    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="failed strict verification",
    ):
        _load(
            authorization_context,
            built,
            publication,
            overrides={"journal": foreign},
        )


def test_receipt_rejects_transport_metadata_tamper_and_success_without_evidence(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)
    wire = built.receipt.transport_binding.model_dump(mode="python", by_alias=True)
    metadata = cast(dict[str, object], wire["jobMetadata"])
    metadata["executionId"] = "exec_" + "0" * 32
    wire["bindingDigest"] = ""
    wire["jobMetadataDigest"] = ""
    with pytest.raises(ValidationError, match="metadata differs"):
        CompactSkillBoundWebAnalysisTransportBinding.model_validate(wire)

    success = _make_success_receipt(authorization_context, tmp_path / "success")
    receipt_wire = success.receipt.model_dump(mode="python", by_alias=True)
    receipt_wire["compiledProposal"] = None
    receipt_wire["receiptId"] = ""
    receipt_wire["receiptDigest"] = ""
    with pytest.raises(ValidationError, match="success lacks proposal evidence"):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(receipt_wire)


def test_receipt_rejects_every_major_binding_group_tamper(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_success_receipt(authorization_context, tmp_path)
    tamper_cases: tuple[tuple[tuple[str, ...], object], ...] = (
        (("admission", "admissionDigest"), "0" * 64),
        (("admission", "preparationDigest"), "0" * 64),
        (
            (
                "initialAuthorizationVerification",
                "liveRequestDigest",
            ),
            "0" * 64,
        ),
        (("pendingClaim", "binding", "claimDigest"), "0" * 64),
        (("capacityPin", "modelSha256"), "0" * 64),
        (("admission", "compactProjectionDigest"), "0" * 64),
        (("liveMaterializationAttestation", "runtimeContainerId"), "c" * 64),
        (("providerChatRequest", "model"), "tampered-model"),
        (("transportBinding", "liveClaimDigest"), "0" * 64),
        (("dispatchObservation", "providerRegistrationDigest"), "0" * 64),
        (("cleanupResult", "resourceAbsenceDigest"), "0" * 64),
        (
            ("intendedTerminalDisposition",),
            WebAnalysisLiveClaimTerminalDisposition.FAILURE,
        ),
    )

    for path, value in tamper_cases:
        wire = deepcopy(built.receipt.model_dump(mode="python", by_alias=True))
        target = wire
        for key in path[:-1]:
            target = cast(dict[str, Any], target[key])
        target[path[-1]] = value
        wire["receiptId"] = ""
        wire["receiptDigest"] = ""
        with pytest.raises(ValidationError):
            CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(wire)


def test_receipt_rejects_provider_route_and_cleanup_digest_tamper(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_success_receipt(authorization_context, tmp_path)

    route_wire = deepcopy(built.receipt.model_dump(mode="python", by_alias=True))
    route = cast(dict[str, object], route_wire["providerRouteAttestation"])
    route.update(
        {
            "attestationDigest": "",
            "claimDigest": _sha("foreign-route-claim"),
        }
    )
    route_wire.update({"receiptId": "", "receiptDigest": ""})
    with pytest.raises(ValidationError, match="Provider route attestation differs"):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(route_wire)

    cleanup_wire = deepcopy(built.receipt.model_dump(mode="python", by_alias=True))
    cleanup = cast(dict[str, object], cleanup_wire["cleanupResult"])
    cleanup.update(
        {
            "cleanupDigest": "",
            "resourceAbsenceDigest": "",
            "providerRouteAttestationDigest": _sha("foreign-route-attestation"),
        }
    )
    cleanup_wire.update({"receiptId": "", "receiptDigest": ""})
    with pytest.raises(ValidationError, match="request, dispatch, or cleanup differs"):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(cleanup_wire)

    missing_wire = deepcopy(built.receipt.model_dump(mode="python", by_alias=True))
    missing_wire.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "providerRouteAttestation": None,
        }
    )
    with pytest.raises(ValidationError, match="success lacks proposal evidence"):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(missing_wire)


def test_terminal_success_requires_response_proposal_authorization_and_attestation(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_success_receipt(authorization_context, tmp_path)
    mutations: tuple[tuple[str, object], ...] = (
        ("compiledProposal", None),
        ("preDispatchAuthorizationVerification", None),
        ("liveMaterializationAttestation", None),
    )
    for key, value in mutations:
        wire = deepcopy(built.receipt.model_dump(mode="python", by_alias=True))
        wire.update({"receiptId": "", "receiptDigest": "", key: value})
        with pytest.raises(ValidationError):
            CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(wire)

    wire = deepcopy(built.receipt.model_dump(mode="python", by_alias=True))
    observation = cast(dict[str, object], wire["dispatchObservation"])
    observation.update(
        {
            "observationDigest": "",
            "responseSha256": None,
            "responseBytes": 0,
            "responseEvidenceAvailable": False,
            "failureDigest": _sha("lost-success-response"),
        }
    )
    wire.update({"receiptId": "", "receiptDigest": ""})
    with pytest.raises(ValidationError):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(wire)


def test_loader_rejects_independent_anchor_substitution(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)
    publication = _publish_and_anchor(
        authorization_context,
        built,
        tmp_path / "terminal",
    )
    built.journal.finalize_terminal(
        built.pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        terminal_receipt_digest=built.receipt.receipt_digest,
    )
    substitutions: tuple[tuple[str, object], ...] = (
        ("expected_receipt_digest", "0" * 64),
        ("expected_claim_digest", "0" * 64),
        ("expected_source_root_digest", "0" * 64),
        ("expected_skill_root_digest", "0" * 64),
        ("expected_capacity_root_digest", "0" * 64),
        ("expected_preparation_root_digest", "0" * 64),
        ("expected_transport_pin_digest", "0" * 64),
        ("expected_compact_runtime_pin_digest", "0" * 64),
        ("expected_compact_transport_pin_digest", "0" * 64),
        ("expected_trust_anchor_digest", "0" * 64),
    )

    for key, value in substitutions:
        with pytest.raises(
            CompactSkillBoundWebAnalysisTerminalReceiptError,
            match="failed strict verification",
        ):
            _load(
                authorization_context,
                built,
                publication,
                overrides={key: value},
            )


def test_receipt_keeps_lineage_and_compact_transport_identities_distinct(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)
    receipt = built.receipt
    lineage_digest = authorization_context.transport_pin.pin_digest
    compact_digest = authorization_context.compact_transport.pin_digest

    assert lineage_digest != compact_digest
    assert receipt.pending_claim.binding.transport_pin_digest == lineage_digest
    assert receipt.admission.transport_pin_digest == lineage_digest
    assert receipt.transport_binding.lineage_transport_pin.pin_digest == lineage_digest
    assert receipt.initial_authorization_verification.lineage_transport_pin_digest == (
        lineage_digest
    )
    assert receipt.initial_authorization_verification.compact_transport_pin_digest == (
        compact_digest
    )
    assert receipt.cleanup_result.transport_cleanup.transport_pin_digest == compact_digest


def test_receipt_rejects_compact_runtime_and_transport_cross_recombination(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)

    runtime_wire = authorization_context.compact_runtime.model_dump(mode="python", by_alias=True)
    runtime_wire.update(
        {
            "pinDigest": "",
            "modelRepository": "foreign.invalid/recombined-model",
        }
    )
    foreign_runtime = type(authorization_context.compact_runtime).model_validate(runtime_wire)
    runtime_receipt = built.receipt.model_dump(mode="python", by_alias=True)
    runtime_receipt.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "compactRuntimePin": foreign_runtime.model_dump(mode="python", by_alias=True),
        }
    )
    with pytest.raises(ValidationError, match="materialization lineage differs"):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(runtime_receipt)

    transport_wire = authorization_context.compact_transport.model_dump(
        mode="python", by_alias=True
    )
    transport_wire.update(
        {
            "pinDigest": "",
            "workerImage": "sha256:" + "f" * 64,
        }
    )
    foreign_transport = type(authorization_context.compact_transport).model_validate(transport_wire)
    transport_receipt = built.receipt.model_dump(mode="python", by_alias=True)
    transport_receipt.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "compactTransportPin": foreign_transport.model_dump(mode="python", by_alias=True),
        }
    )
    with pytest.raises(ValidationError, match="request, dispatch, or cleanup differs"):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(transport_receipt)


def test_v1alpha1_receipt_binding_index_and_authorization_are_not_live_authoritative(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path / "claim")

    binding_wire = built.receipt.transport_binding.model_dump(mode="python", by_alias=True)
    binding_wire["apiVersion"] = (
        "pajin.dev/compact-skill-bound-web-analysis-transport-binding/v1alpha1"
    )
    with pytest.raises(ValidationError):
        CompactSkillBoundWebAnalysisTransportBinding.model_validate(binding_wire)

    receipt_wire = built.receipt.model_dump(mode="python", by_alias=True)
    receipt_wire["apiVersion"] = (
        "pajin.dev/compact-skill-bound-web-analysis-terminal-receipt/v1alpha1"
    )
    with pytest.raises(ValidationError):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(receipt_wire)

    legacy_authorization_receipt = built.receipt.model_dump(mode="python", by_alias=True)
    signed = cast(dict[str, object], legacy_authorization_receipt["signedAuthorization"])
    signed["apiVersion"] = "pajin.dev/web-analysis-one-call-authorization-bundle/v1alpha1"
    signed["kind"] = "SignedWebAnalysisOneCallAuthorization"
    with pytest.raises(ValidationError):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(legacy_authorization_receipt)

    publication = publish_compact_skill_bound_web_analysis_terminal_run(
        tmp_path / "terminal",
        receipt=built.receipt,
        signed_authorization=built.bundle,
        draft=None,
        proposal=None,
    )
    index_wire = json.loads(
        (publication.run_path / "compact-live-terminal-index.json").read_text(encoding="utf-8")
    )
    index_wire["apiVersion"] = "pajin.dev/compact-skill-bound-web-analysis-terminal-index/v1alpha1"
    with pytest.raises(ValidationError):
        CompactSkillBoundWebAnalysisTerminalIndex.model_validate(index_wire)


def test_cleanup_binding_rejects_stale_foreign_and_substituted_evidence(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)
    mutations: tuple[tuple[str, object], ...] = (
        ("claimStoreId", _sha("foreign-claim-store")),
        ("claimDigest", _sha("foreign-claim")),
        ("pendingClaimStateDigest", _sha("stale-pre-attempt-state")),
        ("dispatchObservationDigest", _sha("foreign-dispatch-observation")),
        ("liveAttestationDigest", _sha("foreign-live-attestation")),
    )
    for field, value in mutations:
        receipt_wire = deepcopy(built.receipt.model_dump(mode="python", by_alias=True))
        cleanup_wire = cast(dict[str, object], receipt_wire["cleanupResult"])
        cleanup_wire.update(
            {
                "cleanupDigest": "",
                "resourceAbsenceDigest": "",
                field: value,
            }
        )
        receipt_wire.update({"receiptId": "", "receiptDigest": ""})
        with pytest.raises(ValidationError, match="request, dispatch, or cleanup differs"):
            CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(receipt_wire)


def test_nonempty_credential_lease_cleanup_is_exact_and_complete(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_success_receipt(authorization_context, tmp_path)
    assert len(built.receipt.transport_binding.lease_ids) == 1
    lease_id = built.receipt.transport_binding.lease_ids[0]
    publication = _publish_and_anchor(
        authorization_context,
        built,
        tmp_path / "terminal",
        draft=built.draft,
        proposal=built.proposal,
    )
    built.journal.finalize_terminal(
        built.pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.SUCCESS,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        terminal_receipt_digest=built.receipt.receipt_digest,
    )
    loaded = _load(authorization_context, built, publication)
    assert loaded.receipt.transport_binding.lease_ids == (lease_id,)
    assert loaded.receipt.cleanup_result.revoked_lease_ids == (lease_id,)

    for revoked in ((), ("lease_" + "2" * 32,)):
        receipt_wire = deepcopy(built.receipt.model_dump(mode="python", by_alias=True))
        cleanup_wire = cast(dict[str, object], receipt_wire["cleanupResult"])
        cleanup_wire.update(
            {
                "cleanupDigest": "",
                "resourceAbsenceDigest": "",
                "revokedLeaseIds": revoked,
            }
        )
        receipt_wire.update({"receiptId": "", "receiptDigest": ""})
        with pytest.raises(ValidationError, match="credential lease identity differs"):
            CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(receipt_wire)

    cleanup_wire = built.cleanup.model_dump(mode="python", by_alias=True)
    cleanup_wire.update(
        {
            "cleanupDigest": "",
            "resourceAbsenceDigest": "",
            "credentialLeasesRevoked": False,
        }
    )
    with pytest.raises(ValidationError, match="literal true"):
        CompactSkillBoundWebAnalysisCleanupResult.model_validate(cleanup_wire)


@pytest.mark.parametrize(
    "tampered_lease_ids",
    ((), ("lease_" + "f" * 32,)),
    ids=("zero", "foreign"),
)
def test_candidate_loader_rejects_self_sealed_dispatched_lease_tamper(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    tampered_lease_ids: tuple[str, ...],
) -> None:
    built = _make_success_receipt(authorization_context, tmp_path / "claim")
    source_publication = publish_compact_skill_bound_web_analysis_terminal_run(
        tmp_path / "source",
        receipt=built.receipt,
        signed_authorization=built.bundle,
        draft=built.draft,
        proposal=built.proposal,
    )

    transport_wire = deepcopy(
        built.receipt.transport_binding.model_dump(mode="python", by_alias=True)
    )
    transport_wire.update(
        {
            "bindingDigest": "",
            "leaseIds": tampered_lease_ids,
            "jobMetadata": expected_compact_web_analysis_transport_job_metadata(
                built.receipt.transport_binding.tool_request,
                capacity_pin=built.receipt.capacity_pin,
                registration=built.receipt.provider_registration,
                live_request=built.receipt.transport_binding.live_request,
                lineage_transport_pin=(built.receipt.transport_binding.lineage_transport_pin),
                runtime_pin=built.receipt.compact_runtime_pin,
                transport_pin=built.receipt.compact_transport_pin,
                expected_capacity_pin_digest=built.receipt.capacity_pin.pin_digest,
                expected_lineage_transport_pin_digest=(
                    built.receipt.transport_binding.lineage_transport_pin.pin_digest
                ),
                expected_runtime_pin_digest=built.receipt.compact_runtime_pin.pin_digest,
                expected_transport_pin_digest=built.receipt.compact_transport_pin.pin_digest,
                execution_id=built.receipt.transport_execution_id,
                lease_ids=list(tampered_lease_ids),
            ),
            "jobMetadataDigest": "",
        }
    )
    transport = CompactSkillBoundWebAnalysisTransportBinding.model_validate(transport_wire)
    observation_wire = built.receipt.dispatch_observation.model_dump(mode="python", by_alias=True)
    observation_wire.update(
        {
            "observationDigest": "",
            "transportBindingDigest": transport.binding_digest,
            "transportJobMetadataDigest": transport.job_metadata_digest,
        }
    )
    observation = CompactSkillBoundWebAnalysisDispatchObservation.model_validate(observation_wire)
    cleanup_wire = built.cleanup.model_dump(mode="python", by_alias=True)
    cleanup_wire.update(
        {
            "cleanupDigest": "",
            "resourceAbsenceDigest": "",
            "dispatchObservationDigest": observation.observation_digest,
            "revokedLeaseIds": tampered_lease_ids,
        }
    )
    cleanup = CompactSkillBoundWebAnalysisCleanupResult.model_validate(cleanup_wire)
    receipt_wire = built.receipt.model_dump(mode="json", by_alias=True)
    receipt_wire.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "transportBinding": transport.model_dump(mode="json", by_alias=True),
            "dispatchObservation": observation.model_dump(mode="json", by_alias=True),
            "cleanupResult": cleanup.model_dump(mode="json", by_alias=True),
        }
    )

    output_root = tmp_path / "target"
    run_path = compact_skill_bound_web_analysis_terminal_run_path(output_root, built.pending)
    intent = built.journal.record_terminal_publication_intent(
        built.pending,
        output_root=output_root,
        run_path=run_path,
        run_id=built.receipt.terminal_run_id,
        receipt_digest=built.receipt.receipt_digest,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        disposition=built.receipt.intended_terminal_disposition,
        live_attestation_digest=built.attestation.attestation_digest,
    )
    source_snapshot = load_verified_run_snapshot(
        source_publication.run_path,
        expected_run_id=source_publication.run_id,
    )
    store = RunStore.create(
        output_root,
        run_path.parent.name,
        run_id=built.receipt.terminal_run_id,
    )
    for event in source_snapshot.events:
        store.append_event(event.event_type, event.payload)
    for artifact in source_snapshot.seals[0].artifacts:
        raw = (source_publication.run_path / artifact.path).read_bytes()
        if artifact.path == "compact-live-terminal-receipt.json":
            raw = (
                json.dumps(
                    receipt_wire,
                    allow_nan=False,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
        store.write_bytes(artifact.path, raw)
    seal = store.seal()
    tampered = SimpleNamespace(
        run_path=store.path,
        run_id=built.receipt.terminal_run_id,
        root_digest=seal.root_digest,
    )

    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="failed strict verification",
    ):
        _load(authorization_context, built, tampered, candidate=True)
    durable = built.journal.inspect_terminal_publication(built.pending.binding.claim_id)
    assert durable == intent
    assert durable is not None and durable.root_digest is None


def test_loader_rejects_gate_d_context_substitution(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)
    receipt_wire = built.receipt.model_dump(mode="python", by_alias=True)
    receipt_wire.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "gateDContextDigest": _sha("substituted-gate-d-context"),
        }
    )
    receipt = CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(receipt_wire)
    substituted = SimpleNamespace(
        bundle=built.bundle,
        journal=built.journal,
        pending=built.pending,
        receipt=receipt,
        cleanup=built.cleanup,
    )
    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="failed strict verification",
    ):
        _publish_and_anchor(
            authorization_context,
            substituted,
            tmp_path / "terminal",
            receipt=receipt,
        )
    durable = built.journal.inspect_terminal_publication(built.pending.binding.claim_id)
    assert durable is not None
    assert durable.root_digest is None


def test_receipt_rejects_copied_initial_authorization_and_wrong_failure_stage(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    successful = _make_success_receipt(authorization_context, tmp_path / "success")
    wire = successful.receipt.model_dump(mode="python", by_alias=True)
    wire.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "preDispatchAuthorizationVerification": wire["initialAuthorizationVerification"],
        }
    )
    with pytest.raises(ValidationError, match="pre-dispatch authorization lineage differs"):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(wire)

    failed = _make_failure_receipt(authorization_context, tmp_path / "failure")
    wire = failed.receipt.model_dump(mode="python", by_alias=True)
    wire.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "failureStage": "dispatch",
        }
    )
    with pytest.raises(ValidationError, match="failure stage differs"):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(wire)

    wire = failed.receipt.model_dump(mode="python", by_alias=True)
    observation = cast(dict[str, object], wire["dispatchObservation"])
    observation.update(
        {
            "observationDigest": "",
            "failureDigest": _sha("substituted-observation-failure"),
        }
    )
    changed_observation = CompactSkillBoundWebAnalysisDispatchObservation.model_validate(
        observation
    )
    resources = failed.pending.binding.resources
    changed_cleanup = _cleanup(
        claim_store_id=failed.journal.store_id,
        claim_digest=failed.pending.binding.claim_digest,
        pending_claim_state_digest=failed.pending.state_digest,
        dispatch_observation_digest=changed_observation.observation_digest,
        live_attestation_digest=None,
        owner=resources.resource_owner,
        runtime_name=resources.runtime_container_name,
        seed_name=resources.seed_container_name,
        volume_name=resources.volume_name,
        network_name=resources.network_name,
        execution_id=failed.receipt.transport_execution_id,
        transport_pin_digest=failed.receipt.compact_transport_pin.pin_digest,
        revoked_lease_ids=failed.receipt.transport_binding.lease_ids,
    )
    wire.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "cleanupResult": changed_cleanup.model_dump(mode="python", by_alias=True),
        }
    )
    with pytest.raises(ValidationError, match="failure binding differs"):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(wire)


def test_loader_rejects_relocated_sealed_terminal_run(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path / "case")
    publication = _publish_and_anchor(
        authorization_context,
        built,
        tmp_path / "terminal",
    )
    built.journal.finalize_terminal(
        built.pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        terminal_receipt_digest=built.receipt.receipt_digest,
    )
    relocated = tmp_path / "relocated" / publication.run_path.parent.name / publication.run_id
    relocated.parent.mkdir(parents=True)
    shutil.copytree(publication.run_path, relocated)
    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="failed strict verification",
    ):
        _load(authorization_context, built, publication, run_path=relocated)


@pytest.mark.parametrize("symlink_component", ["run", "campaign", "output-root", "ancestor"])
def test_loader_rejects_deterministic_path_relocated_through_symlink(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    symlink_component: str,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path / "claim")
    lexical_parent = tmp_path / "trusted-parent"
    output_root = lexical_parent / "terminal"
    publication = _publish_and_anchor(
        authorization_context,
        built,
        output_root,
    )
    built.journal.finalize_terminal(
        built.pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        terminal_receipt_digest=built.receipt.receipt_digest,
    )

    if symlink_component == "run":
        source = publication.run_path
        relocated = tmp_path / "relocated-run"
    elif symlink_component == "campaign":
        source = publication.run_path.parent
        relocated = tmp_path / "relocated-campaign"
    elif symlink_component == "output-root":
        source = output_root
        relocated = tmp_path / "relocated-output-root"
    else:
        source = lexical_parent
        relocated = tmp_path / "relocated-parent"
    shutil.move(source, relocated)
    source.symlink_to(relocated, target_is_directory=True)

    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="failed strict verification",
    ):
        _load(authorization_context, built, publication)


@pytest.mark.parametrize("symlink_component", ("output-root", "ancestor"))
def test_publisher_rejects_preexisting_root_symlink_before_writing(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    symlink_component: str,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path / "claim")
    relocated = tmp_path / "relocated"
    relocated.mkdir()
    if symlink_component == "output-root":
        trusted_parent = tmp_path / "trusted-parent"
        trusted_parent.mkdir()
        output_root = trusted_parent / "terminal"
        output_root.symlink_to(relocated, target_is_directory=True)
    else:
        trusted_parent = tmp_path / "trusted-parent"
        trusted_parent.symlink_to(relocated, target_is_directory=True)
        output_root = trusted_parent / "terminal"

    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="publication failed closed",
    ):
        publish_compact_skill_bound_web_analysis_terminal_run(
            output_root,
            receipt=built.receipt,
            signed_authorization=built.bundle,
            draft=None,
            proposal=None,
        )

    assert tuple(relocated.iterdir()) == ()


def test_loader_compares_index_hashes_to_raw_snapshot_bytes(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path / "case")
    publication = _publish_and_anchor(
        authorization_context,
        built,
        tmp_path / "terminal",
    )
    built.journal.finalize_terminal(
        built.pending,
        disposition=WebAnalysisLiveClaimTerminalDisposition.ABANDONED,
        cleanup_result_digest=built.cleanup.cleanup_digest,
        resource_absence_digest=built.cleanup.resource_absence_digest,
        terminal_receipt_digest=built.receipt.receipt_digest,
    )
    source_snapshot = load_verified_run_snapshot(
        publication.run_path,
        expected_run_id=publication.run_id,
    )
    output_root = tmp_path / "raw-byte-mismatch"
    store = RunStore.create(
        output_root,
        publication.run_path.parent.name,
        run_id=publication.run_id,
    )
    for event in source_snapshot.events:
        store.append_event(event.event_type, event.payload)
    for artifact in source_snapshot.seals[0].artifacts:
        raw = (publication.run_path / artifact.path).read_bytes()
        if artifact.path == "compact-live-terminal-receipt.json":
            raw = json.dumps(
                json.loads(raw),
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        store.write_bytes(artifact.path, raw)
    seal = store.seal()
    noncanonical = SimpleNamespace(
        run_path=store.path,
        run_id=publication.run_id,
        root_digest=seal.root_digest,
    )
    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="failed strict verification",
    ):
        _load(authorization_context, built, noncanonical)


def test_full_claim_parent_isolates_truncated_run_id_collisions(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    built = _make_failure_receipt(authorization_context, tmp_path)
    first = built.pending
    first_digest = first.binding.claim_digest
    colliding_digest = (
        first_digest[:8] + ("0" if first_digest[8] != "0" else "1") + first_digest[9:]
    )
    colliding_binding = first.binding.model_copy(update={"claim_digest": colliding_digest})
    colliding = first.model_copy(update={"binding": colliding_binding})
    assert compact_skill_bound_web_analysis_terminal_run_id(first) == (
        compact_skill_bound_web_analysis_terminal_run_id(colliding)
    )
    first_path = compact_skill_bound_web_analysis_terminal_run_path(tmp_path, first)
    colliding_path = compact_skill_bound_web_analysis_terminal_run_path(tmp_path, colliding)
    assert first_path != colliding_path
    assert first_digest in first_path.parent.name
    assert colliding_digest in colliding_path.parent.name


def test_new_terminal_wire_is_incompatible_with_legacy_receipt(
    authorization_context: SimpleNamespace,
    sample_campaign: CampaignManifest,
    tmp_path: Path,
) -> None:
    built = _make_success_receipt(authorization_context, tmp_path)
    current_wire = built.receipt.model_dump(mode="python", by_alias=True)
    with pytest.raises(ValidationError):
        SkillBoundWebAnalysisInvocationReceipt.model_validate(current_wire)
    current_publication = publish_compact_skill_bound_web_analysis_terminal_run(
        tmp_path / "current-terminal",
        receipt=built.receipt,
        signed_authorization=built.bundle,
        draft=built.draft,
        proposal=built.proposal,
    )

    legacy_case = _build_legacy_case(
        tmp_path / "legacy",
        sample_campaign,
        authorization_context.source,
        content=None,
    )
    legacy_case.gateway.content = _legacy_successor_content(legacy_case.skill_run)
    legacy_completion = asyncio.run(
        _invoke_legacy_runtime(_legacy_runtime(legacy_case), legacy_case)
    )
    assert type(legacy_completion.receipt) is SkillBoundWebAnalysisInvocationReceipt
    legacy_wire = legacy_completion.receipt.model_dump(mode="python", by_alias=True)
    with pytest.raises(ValidationError):
        CompactSkillBoundWebAnalysisTerminalReceipt.model_validate(legacy_wire)
    legacy_provider_publication = legacy_completion.provider_publication
    with pytest.raises(SkillBoundWebAnalysisRuntimeError):
        load_verified_skill_bound_web_analysis_invocation(
            current_publication.run_path,
            expected_run_id=current_publication.run_id,
            expected_root_digest=current_publication.root_digest,
            source=legacy_case.source,
            skill_run=legacy_case.skill_run,
            transport_pin=legacy_case.transport_pin,
            registration=legacy_case.provider_runtime.base_runtime.registration,
            provider_run_path=legacy_provider_publication.run_path,
            expected_provider_run_id=legacy_provider_publication.run_id,
            expected_provider_root_digest=legacy_provider_publication.root_digest,
            expected_provider_execution_context=(legacy_case.provider_runtime.execution_context),
            expected_source_run_id=legacy_case.source.verification.run_id,
            expected_source_root_digest=legacy_case.source.verification.root_digest,
            expected_skill_run_id=legacy_case.skill_run.verification.run_id,
            expected_skill_root_digest=legacy_case.skill_run.verification.root_digest,
            expected_registry_ref=legacy_case.skill_run.index.registry,
            expected_policy_digest=legacy_case.skill_run.index.selection_policy_digest,
            expected_transport_pin_digest=legacy_case.transport_pin.pin_digest,
            expected_external_network=_EXPECTED_EXTERNAL_NETWORK,
        )
    with pytest.raises(
        CompactSkillBoundWebAnalysisTerminalReceiptError,
        match="failed strict verification",
    ):
        _load(
            authorization_context,
            built,
            legacy_completion.publication,
            pending=True,
        )


def test_receipt_module_has_no_forbidden_legacy_runtime_imports() -> None:
    path = PROJECT_ROOT / "src/pajin/web_assessment/analysis_skill_compact_live_receipts.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    forbidden = {
        "pajin.web_assessment.analysis_skill_runtime",
        "pajin.web_assessment.analysis_skill_receipts",
        "pajin.web_assessment.analysis_runtime",
        "pajin.web_assessment.analysis_local",
        "pajin.benchmark.effectiveness.docker",
        "pajin.benchmark.effectiveness.suite",
    }
    assert imports.isdisjoint(forbidden)
    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert imported_names.isdisjoint(
        {
            "RuntimePin",
            "SignedWebAnalysisOneCallAuthorization",
            "VerifiedWebAnalysisOneCallAuthorization",
            "WebAnalysisOneCallAuthorizationVerifier",
            "expected_web_analysis_provider_worker_context",
            "expected_web_analysis_transport_job_metadata",
            "prepare_web_analysis_transport_job",
        }
    )
