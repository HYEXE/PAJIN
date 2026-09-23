from __future__ import annotations

import ast
import asyncio
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import JsonValue

import pajin.web_assessment.analysis_skill_compact_live_runtime as runtime_module
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import ToolRequest
from pajin.providers.models import ProviderChatRequest, ProviderChatResult, ProviderRegistration
from pajin.runtime.secrets import SecretBroker, SecretLeaseStatus
from pajin.runtime.worker import (
    DockerPreCleanupBarrierDeadlineExceeded,
    DockerPreCleanupBarrierError,
    DockerWorkerBackend,
    WorkerCleanupError,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.web_assessment.analysis_capacity_v2 import (
    VerifiedWebAnalysisCapacityV2Run,
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
from pajin.web_assessment.analysis_live_authorization_v2 import (
    SignedWebAnalysisOneCallAuthorizationV2,
    WebAnalysisOneCallAuthorizationVerifierV2,
)
from pajin.web_assessment.analysis_live_claim_journal import (
    DispatchStartedWebAnalysisLiveClaim,
    WebAnalysisLiveClaimBinding,
    WebAnalysisLiveClaimJournal,
    WebAnalysisLiveClaimJournalEntry,
    WebAnalysisLiveClaimJournalError,
    WebAnalysisLiveClaimPendingOutcome,
    WebAnalysisLiveClaimPhase,
    WebAnalysisLiveClaimTerminalDisposition,
    build_web_analysis_live_claim_binding,
)
from pajin.web_assessment.analysis_skill_compact import (
    build_compact_skill_bound_web_analysis_chat_request,
)
from pajin.web_assessment.analysis_skill_compact_live_receipts import (
    CompactSkillBoundWebAnalysisDispatchObservation,
    CompactSkillBoundWebAnalysisTransportBinding,
    compact_skill_bound_web_analysis_terminal_run_path,
)
from pajin.web_assessment.analysis_skill_compact_live_runtime import (
    CompactSkillBoundWebAnalysisCleanupBlockedError,
    CompactSkillBoundWebAnalysisDispatchSettlement,
    CompactSkillBoundWebAnalysisLiveAnchors,
    CompactSkillBoundWebAnalysisLiveRuntime,
    CompactSkillBoundWebAnalysisLiveRuntimeError,
    CompactSkillBoundWebAnalysisPreparedContext,
    CompactSkillBoundWebAnalysisPreparedDispatch,
    CompactSkillBoundWebAnalysisProcessedResponse,
    DockerCompactSkillBoundWebAnalysisDispatchAdapter,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportCleanupProof,
    web_analysis_transport_pre_cleanup_barrier_context,
)
from tests.test_web_analysis_live_authorization_v2 import (
    _NOW,
    _signed,
    _statement,
)
from tests.test_web_analysis_skill_invocation import _successor_draft_payload
from tests.test_web_analysis_skill_live_invocation import _admission_anchors

pytest_plugins = ("tests.test_web_analysis_live_authorization_v2",)


class _AdvancingClock:
    def __init__(self, *values: datetime) -> None:
        self._values = list(values)
        self._last = values[-1]

    def __call__(self) -> datetime:
        if self._values:
            self._last = self._values.pop(0)
        else:
            self._last += timedelta(seconds=1)
        return self._last


@pytest.fixture(scope="module")  # type: ignore[untyped-decorator]
def authorization_context(authorization_v2_context: SimpleNamespace) -> SimpleNamespace:
    return authorization_v2_context


def _anchors(
    context: SimpleNamespace,
    *,
    trust_anchor_digest: str,
    claim_store_id: str,
) -> CompactSkillBoundWebAnalysisLiveAnchors:
    values = _admission_anchors(
        context.source,
        context.skill_run,
        context.capacity,
        context.preparation,
    )
    return CompactSkillBoundWebAnalysisLiveAnchors(
        source_run_id=cast(str, values["expected_source_run_id"]),
        source_root_digest=cast(str, values["expected_source_root_digest"]),
        skill_run_id=cast(str, values["expected_skill_run_id"]),
        skill_root_digest=cast(str, values["expected_skill_root_digest"]),
        registry_ref=context.skill_run.index.registry,
        policy_digest=cast(str, values["expected_policy_digest"]),
        capacity_run_id=cast(str, values["expected_capacity_run_id"]),
        capacity_root_digest=cast(str, values["expected_capacity_root_digest"]),
        capacity_pin_digest=cast(str, values["expected_capacity_pin_digest"]),
        capacity_proof_digest=cast(str, values["expected_capacity_proof_digest"]),
        capacity_materialization_attestation_digest=cast(
            str,
            values["expected_capacity_model_materialization_attestation_digest"],
        ),
        lineage_transport_pin_digest=cast(str, values["expected_transport_pin_digest"]),
        compact_runtime_pin_digest=context.compact_runtime.pin_digest,
        compact_transport_pin_digest=context.compact_transport.pin_digest,
        preparation_run_id=cast(str, values["expected_preparation_run_id"]),
        preparation_root_digest=cast(str, values["expected_preparation_root_digest"]),
        preparation_digest=cast(str, values["expected_preparation_digest"]),
        preparation_index_digest=cast(str, values["expected_preparation_index_digest"]),
        live_request_digest=cast(str, values["expected_live_request_digest"]),
        trust_anchor_digest=trust_anchor_digest,
        claim_store_id=claim_store_id,
    )


class _FakeMaterializer:
    def __init__(
        self,
        context: SimpleNamespace,
        owner: str,
        events: list[str],
        *,
        cleanup_fails: bool = False,
        reattest_fails: bool = False,
        route_mode: str = "exact",
    ) -> None:
        self._context = context
        self._owner = owner
        self._events = events
        self._cleanup_fails = cleanup_fails
        self._reattest_fails = reattest_fails
        self._route_mode = route_mode
        self._attestation: WebAnalysisLiveModelMaterializationAttestation | None = None

    @property
    def resources(self) -> tuple[str, str, str, str]:
        owner = self._owner
        return (
            f"pajin-web-analysis-live-{owner}",
            f"pajin-web-analysis-live-seed-{owner}",
            f"pajin-web-analysis-live-model-{owner}",
            f"pajin-web-analysis-live-network-{owner}",
        )

    def materialize(self, capacity_run: VerifiedWebAnalysisCapacityV2Run) -> None:
        self._events.append("materialize")
        assert capacity_run == self._context.capacity

    def live_attestation(self) -> WebAnalysisLiveModelMaterializationAttestation:
        self._events.append("attest")
        if self._attestation is None:
            runtime_name, _, volume_name, network_name = self.resources
            pin = self._context.capacity_pin
            self._attestation = WebAnalysisLiveModelMaterializationAttestation(
                capacityRunId=self._context.capacity.run_id,
                capacityRootDigest=self._context.capacity.root_digest,
                capacityPinDigest=pin.pin_digest,
                capacityProofDigest=self._context.capacity.proof.proof_digest,
                capacityMaterializationAttestationDigest=(
                    self._context.capacity.model_materialization_attestation_digest
                ),
                modelPinDigest=pin.model_pin_digest,
                modelSha256=pin.model_sha256,
                modelSizeBytes=pin.model_size_bytes,
                descriptorIdentityDigest=sha256(b"test held descriptor identity").hexdigest(),
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
                resourceOwner=self._owner,
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
        return self._attestation

    def reattest_provider_route(
        self,
        *,
        claim_digest: str,
        resource_owner: str,
        provider_registration_digest: str,
        provider_endpoint: str,
    ) -> WebAnalysisLiveModelProviderRouteAttestation:
        self._events.append("route-reattest")
        if self._reattest_fails:
            raise RuntimeError("injected Provider route reattestation failure")
        assert self._attestation is not None
        assert resource_owner == self._owner
        assert (
            provider_registration_digest == self._context.live_request.provider_registration_digest
        )
        assert provider_endpoint == str(self._context.live_request.provider_registration.endpoint)
        if self._route_mode == "missing":
            return cast(Any, None)
        if self._route_mode == "no-alias":
            raise RuntimeError("injected missing Provider network alias")
        if self._route_mode == "foreign-member":
            raise RuntimeError("injected foreign live-model network member")
        exact_claim_digest = (
            sha256(b"tampered route claim").hexdigest()
            if self._route_mode == "tampered"
            else claim_digest
        )
        return WebAnalysisLiveModelProviderRouteAttestation(
            claimDigest=exact_claim_digest,
            resourceOwner=resource_owner,
            liveMaterializationAttestationDigest=self._attestation.attestation_digest,
            runtimeContainerName=self._attestation.runtime_container_name,
            runtimeContainerId=self._attestation.runtime_container_id,
            networkName=self._attestation.network_name,
            networkId=self._attestation.network_id,
            providerRegistrationDigest=provider_registration_digest,
            providerEndpoint=provider_endpoint,
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

    def cleanup_owned_resources_and_verify_absent(
        self,
    ) -> tuple[
        WebAnalysisLiveModelCleanupOnlyResult,
        WebAnalysisLiveModelResourceAbsenceProof,
    ]:
        self._events.append("model-cleanup")
        if self._cleanup_fails:
            raise RuntimeError("injected model cleanup failure")
        runtime_name, seed_name, volume_name, network_name = self.resources
        absence = WebAnalysisLiveModelResourceAbsenceProof(
            resourceOwner=self._owner,
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
        cleanup = WebAnalysisLiveModelCleanupOnlyResult(
            resourceOwner=self._owner,
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
        return cleanup, absence


class _FakeDispatchAdapter:
    def __init__(
        self,
        context: SimpleNamespace,
        events: list[str],
        *,
        cleanup_blocks: bool = False,
        dispatch_mode: str = "success",
        binding_mode: str = "exact",
    ) -> None:
        self._context = context
        self._events = events
        self._cleanup_blocks = cleanup_blocks
        self._dispatch_mode = dispatch_mode
        self._binding_mode = binding_mode
        self._lineage_transport_pin = context.transport_pin
        self._compact_runtime_pin = context.compact_runtime
        self._compact_transport_pin = context.compact_transport
        self._journal: WebAnalysisLiveClaimJournal | None = None
        self._binding: WebAnalysisLiveClaimBinding | None = None
        self._registration: ProviderRegistration | None = None
        self._result_processor: (
            Callable[[WorkerResult], CompactSkillBoundWebAnalysisProcessedResponse] | None
        ) = None
        self._transport_binding: CompactSkillBoundWebAnalysisTransportBinding | None = None
        self.dispatch_calls = 0
        self.restore_calls = 0
        self.prepared: CompactSkillBoundWebAnalysisPreparedDispatch | None = None
        self.chat: ProviderChatRequest | None = None

    def prepare(
        self,
        *,
        binding: WebAnalysisLiveClaimBinding,
        journal: WebAnalysisLiveClaimJournal,
        registration: ProviderRegistration,
        chat: ProviderChatRequest,
        result_processor: Callable[[WorkerResult], CompactSkillBoundWebAnalysisProcessedResponse],
    ) -> CompactSkillBoundWebAnalysisPreparedDispatch:
        self._events.append("prepare")
        self._journal = journal
        self._binding = binding
        self._registration = registration
        self._result_processor = result_processor
        self.chat = chat
        execution_id = f"exec_{binding.resources.resource_owner}"
        request = ToolRequest(
            request_id=f"tool_{binding.resources.resource_owner}",
            agent_id="web-analysis-compact-live",
            tool_id=f"provider.{registration.provider_id}.chat",
            target=str(registration.endpoint),
            method="POST",
            arguments=chat.model_dump(mode="python", by_alias=True),
        )
        job = prepare_compact_web_analysis_transport_job(
            request,
            registration=registration,
            capacity_pin=self._context.capacity_pin,
            lineage_transport_pin=self._lineage_transport_pin,
            expected_capacity_pin_digest=self._context.capacity_pin.pin_digest,
            expected_lineage_transport_pin_digest=self._lineage_transport_pin.pin_digest,
            live_request=self._context.live_request,
            runtime_pin=self._compact_runtime_pin,
            transport_pin=self._compact_transport_pin,
            expected_runtime_pin_digest=self._compact_runtime_pin.pin_digest,
            expected_transport_pin_digest=self._compact_transport_pin.pin_digest,
            execution_id=execution_id,
        )
        worker_context = expected_compact_web_analysis_provider_worker_context(
            self._compact_runtime_pin,
            self._compact_transport_pin,
            capacity_pin=self._context.capacity_pin,
            lineage_transport_pin=self._lineage_transport_pin,
            expected_capacity_pin_digest=self._context.capacity_pin.pin_digest,
            expected_lineage_transport_pin_digest=self._lineage_transport_pin.pin_digest,
            expected_runtime_pin_digest=self._compact_runtime_pin.pin_digest,
            expected_transport_pin_digest=self._compact_transport_pin.pin_digest,
            live_request=self._context.live_request,
            external_network=binding.resources.network_name,
            claim_digest=binding.claim_digest,
            execution_id=execution_id,
        )
        assert len(job.secret_requests) == 1
        exact_lease_id = runtime_module._deterministic_lease_id(
            claim_digest=binding.claim_digest,
            secret_ref=job.secret_requests[0].secret_ref,
            binding=job.secret_requests[0].binding,
        )
        metadata = expected_compact_web_analysis_transport_job_metadata(
            request,
            registration=registration,
            capacity_pin=self._context.capacity_pin,
            lineage_transport_pin=self._lineage_transport_pin,
            expected_capacity_pin_digest=self._context.capacity_pin.pin_digest,
            expected_lineage_transport_pin_digest=self._lineage_transport_pin.pin_digest,
            live_request=self._context.live_request,
            runtime_pin=self._compact_runtime_pin,
            transport_pin=self._compact_transport_pin,
            expected_runtime_pin_digest=self._compact_runtime_pin.pin_digest,
            expected_transport_pin_digest=self._compact_transport_pin.pin_digest,
            execution_id=execution_id,
            lease_ids=[exact_lease_id],
        )
        self._transport_binding = CompactSkillBoundWebAnalysisTransportBinding(
            liveRequest=self._context.live_request,
            capacityPin=self._context.capacity_pin,
            lineageTransportPin=self._lineage_transport_pin,
            compactRuntimePin=self._compact_runtime_pin,
            compactRuntimePinDigest=self._compact_runtime_pin.pin_digest,
            toolRequest=request,
            providerRegistration=registration,
            compactTransportPin=self._compact_transport_pin,
            compactTransportPinDigest=self._compact_transport_pin.pin_digest,
            liveClaimDigest=binding.claim_digest,
            transportExecutionId=execution_id,
            externalNetwork=binding.resources.network_name,
            leaseIds=(exact_lease_id,),
            workerContext=worker_context,
            workerContextDigest="",
            jobMetadata=cast(dict[str, JsonValue], metadata),
            jobMetadataDigest="",
            secretMaterialEmbedded=False,
            externalEgressAuthority=False,
        )
        barrier_context = web_analysis_transport_pre_cleanup_barrier_context(
            claim_digest=binding.claim_digest,
            execution_id=execution_id,
        )
        self.prepared = CompactSkillBoundWebAnalysisPreparedDispatch(
            request=request,
            job=job,
            execution_id=execution_id,
            external_network=binding.resources.network_name,
            barrier_context=barrier_context,
            worker_context=worker_context,
        )
        return self.prepared

    def stage_one_call(self, prepared: CompactSkillBoundWebAnalysisPreparedDispatch) -> None:
        self._events.append("stage")

    def revalidate_prepared(self, prepared: CompactSkillBoundWebAnalysisPreparedDispatch) -> None:
        self._events.append("revalidate")

    def prepared_context(
        self, prepared: CompactSkillBoundWebAnalysisPreparedDispatch
    ) -> CompactSkillBoundWebAnalysisPreparedContext:
        self._events.append("prepared-context")
        assert self._transport_binding is not None
        if self._binding_mode == "foreign-self-consistent":
            foreign_claim = sha256(b"foreign compact live claim").hexdigest()
            foreign_network = f"pajin-web-analysis-live-network-{'f' * 32}"
            foreign_worker_context = expected_compact_web_analysis_provider_worker_context(
                self._compact_runtime_pin,
                self._compact_transport_pin,
                capacity_pin=self._context.capacity_pin,
                lineage_transport_pin=self._lineage_transport_pin,
                expected_capacity_pin_digest=self._context.capacity_pin.pin_digest,
                expected_lineage_transport_pin_digest=self._lineage_transport_pin.pin_digest,
                expected_runtime_pin_digest=self._compact_runtime_pin.pin_digest,
                expected_transport_pin_digest=self._compact_transport_pin.pin_digest,
                live_request=self._context.live_request,
                external_network=foreign_network,
                claim_digest=foreign_claim,
                execution_id=self._transport_binding.transport_execution_id,
            )
            return CompactSkillBoundWebAnalysisPreparedContext(
                transport_binding=CompactSkillBoundWebAnalysisTransportBinding(
                    liveRequest=self._transport_binding.live_request,
                    capacityPin=self._transport_binding.capacity_pin,
                    lineageTransportPin=self._transport_binding.lineage_transport_pin,
                    compactRuntimePin=self._transport_binding.compact_runtime_pin,
                    compactRuntimePinDigest=(self._transport_binding.compact_runtime_pin_digest),
                    toolRequest=self._transport_binding.tool_request,
                    providerRegistration=self._transport_binding.provider_registration,
                    compactTransportPin=self._transport_binding.compact_transport_pin,
                    compactTransportPinDigest=(
                        self._transport_binding.compact_transport_pin_digest
                    ),
                    liveClaimDigest=foreign_claim,
                    transportExecutionId=self._transport_binding.transport_execution_id,
                    externalNetwork=foreign_network,
                    leaseIds=self._transport_binding.lease_ids,
                    workerContext=foreign_worker_context,
                    workerContextDigest="",
                    jobMetadata=self._transport_binding.job_metadata,
                    jobMetadataDigest="",
                    secretMaterialEmbedded=False,
                    externalEgressAuthority=False,
                )
            )
        if self._binding_mode in {"zero-lease", "foreign-lease"}:
            lease_ids = () if self._binding_mode == "zero-lease" else (f"lease_{'e' * 32}",)
            assert self._registration is not None
            metadata = expected_compact_web_analysis_transport_job_metadata(
                self._transport_binding.tool_request,
                registration=self._registration,
                capacity_pin=self._context.capacity_pin,
                lineage_transport_pin=self._lineage_transport_pin,
                expected_capacity_pin_digest=self._context.capacity_pin.pin_digest,
                expected_lineage_transport_pin_digest=self._lineage_transport_pin.pin_digest,
                live_request=self._context.live_request,
                runtime_pin=self._compact_runtime_pin,
                transport_pin=self._compact_transport_pin,
                expected_runtime_pin_digest=self._compact_runtime_pin.pin_digest,
                expected_transport_pin_digest=self._compact_transport_pin.pin_digest,
                execution_id=self._transport_binding.transport_execution_id,
                lease_ids=list(lease_ids),
            )
            return CompactSkillBoundWebAnalysisPreparedContext(
                transport_binding=CompactSkillBoundWebAnalysisTransportBinding(
                    liveRequest=self._transport_binding.live_request,
                    capacityPin=self._transport_binding.capacity_pin,
                    lineageTransportPin=self._transport_binding.lineage_transport_pin,
                    compactRuntimePin=self._transport_binding.compact_runtime_pin,
                    compactRuntimePinDigest=(self._transport_binding.compact_runtime_pin_digest),
                    toolRequest=self._transport_binding.tool_request,
                    providerRegistration=self._transport_binding.provider_registration,
                    compactTransportPin=self._transport_binding.compact_transport_pin,
                    compactTransportPinDigest=(
                        self._transport_binding.compact_transport_pin_digest
                    ),
                    liveClaimDigest=self._transport_binding.live_claim_digest,
                    transportExecutionId=self._transport_binding.transport_execution_id,
                    externalNetwork=self._transport_binding.external_network,
                    leaseIds=lease_ids,
                    workerContext=self._transport_binding.worker_context,
                    workerContextDigest="",
                    jobMetadata=cast(dict[str, JsonValue], metadata),
                    jobMetadataDigest="",
                    secretMaterialEmbedded=False,
                    externalEgressAuthority=False,
                )
            )
        return CompactSkillBoundWebAnalysisPreparedContext(
            transport_binding=self._transport_binding
        )

    def restore_recovery_context(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        lease_ids: tuple[str, ...],
        transport_binding_digest: str,
        worker_context_digest: str,
        job_metadata_digest: str,
    ) -> None:
        self._events.append("restore")
        self.restore_calls += 1
        assert self._transport_binding is not None
        assert lease_ids == self._transport_binding.lease_ids
        assert transport_binding_digest == self._transport_binding.binding_digest
        assert worker_context_digest == self._transport_binding.worker_context_digest
        assert job_metadata_digest == self._transport_binding.job_metadata_digest

    def restore_possible_pre_context_recovery(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
    ) -> None:
        self._events.append("restore-possible-pre-context")
        self.restore_calls += 1

    async def dispatch_one(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        handle: DispatchStartedWebAnalysisLiveClaim,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement:
        self._events.append("dispatch")
        self.dispatch_calls += 1
        assert self.dispatch_calls == 1
        if self._dispatch_mode == "raise":
            raise RuntimeError("injected fake dispatch uncertainty")
        if self._dispatch_mode == "cancel":
            raise asyncio.CancelledError
        assert self._journal is not None
        assert self._binding is not None
        assert self._registration is not None
        assert self._result_processor is not None
        outcome = (
            WebAnalysisLiveClaimPendingOutcome.FAILURE_OBSERVED
            if self._dispatch_mode == "invalid-response"
            else WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
        )
        pending = self._journal.mark_pending_cleanup(handle, outcome=outcome)
        self._events.append("pending")
        if self._cleanup_blocks:
            pending = self._journal.record_cleanup_failure(
                pending,
                failure_digest=sha256(b"injected transport cleanup failure").hexdigest(),
            )
            raise CompactSkillBoundWebAnalysisCleanupBlockedError(
                "injected transport cleanup failure",
                pending_claim=pending,
            )
        if self._dispatch_mode == "invalid-response":
            failure = sha256(b"injected invalid Provider response").hexdigest()
            cleanup = self._transport_cleanup(prepared)
            self._events.append("transport-cleanup")
            return self._settlement(
                pending,
                cleanup=cleanup,
                processed=None,
                failure_stage="response-validation",
                failure_digest=failure,
            )
        draft_wire = canonical_json_bytes(
            _successor_draft_payload(self._context.skill_run),
            label="fake compact live draft",
        )
        provider = ProviderChatResult(
            provider_id=self._registration.provider_id,
            response_id="fake-response-1",
            model=self._registration.model,
            content=draft_wire.decode("utf-8"),
            refusal=None,
            finish_reason="stop",
            tool_calls=[],
            usage=None,
            streamed=False,
            chunks=1,
            target=prepared.request.target,
        )
        now = _NOW + timedelta(seconds=35)
        raw = WorkerResult(
            execution_id=prepared.execution_id,
            backend="docker",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=provider.model_dump_json(),
            network_log="trusted fake-only network log",
            started_at=now,
            finished_at=now,
        )
        processed = self._result_processor(raw)
        cleanup = self._transport_cleanup(prepared)
        self._events.append("transport-cleanup")
        return self._settlement(
            pending,
            cleanup=cleanup,
            processed=processed,
            failure_stage=None,
            failure_digest=None,
        )

    def settle_without_dispatch(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        pending_claim: WebAnalysisLiveClaimJournalEntry,
        failure_stage: runtime_module._FailureStage,
        failure_digest: str,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement:
        self._events.append("settle-without-dispatch")
        cleanup = self._transport_cleanup(prepared)
        self._events.append("transport-cleanup")
        return self._settlement(
            pending_claim,
            cleanup=cleanup,
            processed=None,
            failure_stage=failure_stage,
            failure_digest=failure_digest,
        )

    def settle_recovery(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        pending_claim: WebAnalysisLiveClaimJournalEntry,
        failure_stage: runtime_module._FailureStage,
        failure_digest: str,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement:
        self._events.append("settle-recovery")
        cleanup = self._transport_cleanup(prepared)
        self._events.append("transport-cleanup")
        return self._settlement(
            pending_claim,
            cleanup=cleanup,
            processed=None,
            failure_stage=failure_stage,
            failure_digest=failure_digest,
        )

    def _transport_cleanup(
        self, prepared: CompactSkillBoundWebAnalysisPreparedDispatch
    ) -> WebAnalysisTransportCleanupProof:
        return WebAnalysisTransportCleanupProof(
            executionId=prepared.execution_id,
            transportPinDigest=self._context.compact_transport.pin_digest,
            externalNetwork=prepared.external_network,
            observedResources=(),
        )

    def _settlement(
        self,
        pending: WebAnalysisLiveClaimJournalEntry,
        *,
        cleanup: WebAnalysisTransportCleanupProof,
        processed: CompactSkillBoundWebAnalysisProcessedResponse | None,
        failure_stage: runtime_module._FailureStage | None,
        failure_digest: str | None,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement:
        assert self._binding is not None
        assert self._registration is not None
        assert self._transport_binding is not None
        assert pending.pending_outcome is not None
        response = None if processed is None else processed.response_bytes
        observation = CompactSkillBoundWebAnalysisDispatchObservation(
            providerId=self._registration.provider_id,
            modelId=self._registration.model,
            transportExecutionId=self._transport_binding.transport_execution_id,
            transportBindingDigest=self._transport_binding.binding_digest,
            transportWorkerContextDigest=self._transport_binding.worker_context_digest,
            transportJobMetadataDigest=self._transport_binding.job_metadata_digest,
            providerRegistrationDigest=self._binding.provider_registration_digest,
            providerChatRequestDigest=self._binding.provider_chat_request_digest,
            pendingOutcome=pending.pending_outcome,
            dispatchCount=pending.dispatch_count,
            responseSha256=None if response is None else sha256(response).hexdigest(),
            responseBytes=0 if response is None else len(response),
            responseEvidenceAvailable=response is not None,
            failureDigest=failure_digest,
        )
        return CompactSkillBoundWebAnalysisDispatchSettlement(
            pending_claim=pending,
            transport_binding=self._transport_binding,
            observation=observation,
            transport_cleanup=cleanup,
            revoked_lease_ids=self._transport_binding.lease_ids,
            draft=None if processed is None else processed.draft,
            proposal=None if processed is None else processed.proposal,
            failure_stage=failure_stage,
            failure_digest=failure_digest,
        )


def _build_runtime(
    context: SimpleNamespace,
    tmp_path: Path,
    *,
    events: list[str] | None = None,
    journal: WebAnalysisLiveClaimJournal | None = None,
    adapter: _FakeDispatchAdapter | None = None,
    cleanup_fails: bool = False,
    reattest_fails: bool = False,
    route_mode: str = "exact",
    binding_mode: str = "exact",
    materializer_factory_fails: bool = False,
    signed_authorization: SignedWebAnalysisOneCallAuthorizationV2 | None = None,
    admission_override: Any | None = None,
    terminal_output_root: Path | None = None,
) -> tuple[
    CompactSkillBoundWebAnalysisLiveRuntime,
    WebAnalysisLiveClaimJournal,
    _FakeDispatchAdapter,
    list[_FakeMaterializer],
]:
    exact_events = [] if events is None else events
    base = _NOW + timedelta(seconds=30)
    exact_journal = journal or WebAnalysisLiveClaimJournal(
        tmp_path / "claim.sqlite3",
        allow_create=True,
        clock=_AdvancingClock(
            base + timedelta(seconds=1),
            base + timedelta(seconds=2),
            base + timedelta(seconds=5),
            base + timedelta(seconds=6),
            base + timedelta(seconds=7),
        ),
    )
    trust_anchor = context.trust_anchor
    verifier = WebAnalysisOneCallAuthorizationVerifierV2(
        trust_anchor=trust_anchor,
        expected_trust_anchor_digest=trust_anchor.digest,
        clock=_AdvancingClock(base, base + timedelta(seconds=4)),
    )
    exact_adapter = adapter or _FakeDispatchAdapter(
        context,
        exact_events,
        binding_mode=binding_mode,
    )
    materializers: list[_FakeMaterializer] = []

    def materializer_factory(owner: str) -> _FakeMaterializer:
        if materializer_factory_fails:
            raise RuntimeError("injected side-effect-free materializer factory failure")
        materializer = _FakeMaterializer(
            context,
            owner,
            exact_events,
            cleanup_fails=cleanup_fails,
            reattest_fails=reattest_fails,
            route_mode=route_mode,
        )
        materializers.append(materializer)
        return materializer

    live = CompactSkillBoundWebAnalysisLiveRuntime(
        source=context.source,
        skill_run=context.skill_run,
        capacity_run=context.capacity,
        preparation_run=context.preparation,
        admission=(context.admission if admission_override is None else admission_override),
        lineage_transport_pin=context.transport_pin,
        compact_runtime_pin=context.compact_runtime,
        compact_transport_pin=context.compact_transport,
        signed_authorization=(
            _signed(context, _statement(context))
            if signed_authorization is None
            else signed_authorization
        ),
        trust_anchor=trust_anchor,
        authorization_verifier=verifier,
        journal=exact_journal,
        materializer_factory=materializer_factory,
        dispatch_adapter=exact_adapter,
        terminal_output_root=(
            tmp_path / "terminal" if terminal_output_root is None else terminal_output_root
        ),
        anchors=_anchors(
            context,
            trust_anchor_digest=trust_anchor.digest,
            claim_store_id=exact_journal.store_id,
        ),
    )
    return live, exact_journal, exact_adapter, materializers


@pytest.mark.asyncio
async def test_success_orders_revalidation_dispatch_cleanup_seal_and_reload(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    live, journal, adapter, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
    )
    original_marker = journal.mark_dispatch_started
    original_finalize = journal.finalize_terminal
    original_publish = cast(
        Callable[..., Any],
        runtime_module.__dict__["publish_compact_skill_bound_web_analysis_terminal_run"],
    )
    original_load = cast(
        Callable[..., Any],
        runtime_module.__dict__["load_verified_compact_skill_bound_web_analysis_terminal_run"],
    )

    def marker(*args: Any, **kwargs: Any) -> Any:
        events.append("dispatch-marker")
        return original_marker(*args, **kwargs)

    def finalize(*args: Any, **kwargs: Any) -> Any:
        events.append("terminal-cas")
        return original_finalize(*args, **kwargs)

    def publish(*args: Any, **kwargs: Any) -> Any:
        events.append("seal-receipt")
        return original_publish(*args, **kwargs)

    def load(*args: Any, **kwargs: Any) -> Any:
        events.append("strict-terminal-reload")
        return original_load(*args, **kwargs)

    monkeypatch.setattr(journal, "mark_dispatch_started", marker)
    monkeypatch.setattr(journal, "finalize_terminal", finalize)
    monkeypatch.setattr(
        runtime_module,
        "publish_compact_skill_bound_web_analysis_terminal_run",
        publish,
    )
    monkeypatch.setattr(
        runtime_module,
        "load_verified_compact_skill_bound_web_analysis_terminal_run",
        load,
    )

    completion = await live.invoke()

    assert adapter.dispatch_calls == 1
    assert completion.dispatch_count == 1
    assert completion.proposal == completion.terminal_run.proposal
    assert completion.terminal_run.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.SUCCESS
    )
    route = completion.terminal_run.receipt.provider_route_attestation
    assert route is not None
    assert (
        completion.terminal_run.gate_d_context.provider_route_attestation_digest
        == route.attestation_digest
        == completion.terminal_run.receipt.cleanup_result.provider_route_attestation_digest
    )
    assert adapter.prepared is not None
    assert adapter.chat is not None
    rebuilt_chat = build_compact_skill_bound_web_analysis_chat_request(
        authorization_context.skill_run.snapshot
    )
    assert adapter.chat == authorization_context.live_request.chat_request == rebuilt_chat
    exact_chat_wire = canonical_json_bytes(
        adapter.chat.model_dump(mode="json", by_alias=True),
        label="exact compact runtime chat",
    )
    assert exact_chat_wire == canonical_json_bytes(
        adapter.prepared.request.arguments,
        label="exact compact runtime Tool request arguments",
    )
    assert len(adapter.prepared.job.secret_requests) == 1
    expected_lease_id = runtime_module._deterministic_lease_id(
        claim_digest=completion.terminal_run.receipt.pending_claim.binding.claim_digest,
        secret_ref=adapter.prepared.job.secret_requests[0].secret_ref,
        binding=adapter.prepared.job.secret_requests[0].binding,
    )
    assert completion.terminal_run.receipt.transport_binding.lease_ids == (expected_lease_id,)
    assert completion.terminal_run.receipt.cleanup_result.revoked_lease_ids == (expected_lease_id,)
    assert [message.role.value for message in adapter.chat.messages] == ["system", "user"]
    assert adapter.chat.tools == []
    assert adapter.chat.tool_choice == "none"
    assert adapter.chat.stream is False
    assert adapter.chat.parallel_tool_calls is False
    assert adapter.chat.max_completion_tokens == 1024
    assert adapter.chat.temperature == 0.0
    assert adapter.chat.top_p == 1.0
    assert adapter.chat.seed == 0
    assert events == [
        "materialize",
        "attest",
        "prepare",
        "stage",
        "revalidate",
        "prepared-context",
        "route-reattest",
        "dispatch-marker",
        "dispatch",
        "pending",
        "transport-cleanup",
        "model-cleanup",
        "seal-receipt",
        "terminal-cas",
        "strict-terminal-reload",
    ]
    with pytest.raises(CompactSkillBoundWebAnalysisLiveRuntimeError, match="already consumed"):
        await live.invoke()
    assert adapter.dispatch_calls == 1


@pytest.mark.asyncio
async def test_side_effect_free_materializer_factory_failure_consumes_no_identity(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    live, journal, adapter, materializers = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
        materializer_factory_fails=True,
    )

    with pytest.raises(RuntimeError, match="materializer factory failure"):
        await live.invoke()

    assert journal.recover_pending_cleanup() == ()
    assert adapter.dispatch_calls == 0
    assert materializers == []
    assert events == []
    assert not (tmp_path / "terminal").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["strict-reload", "authorization"])
async def test_preclaim_failure_has_zero_live_authority(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    failure: str,
) -> None:
    events: list[str] = []
    forged_admission = None
    authorization = None
    if failure == "strict-reload":
        forged_admission = authorization_context.admission.model_copy(
            update={"admission_digest": "f" * 64}
        )
    else:
        authorization = _signed(
            authorization_context,
            _statement(
                authorization_context,
                expires_at=_NOW + timedelta(seconds=10),
            ),
        )
    live, journal, adapter, materializers = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
        admission_override=forged_admission,
        signed_authorization=authorization,
    )

    with pytest.raises((ValueError, CompactSkillBoundWebAnalysisLiveRuntimeError)):
        await live.invoke()

    assert journal.recover_pending_cleanup() == ()
    assert adapter.dispatch_calls == 0
    assert materializers == []
    assert events == []
    assert not (tmp_path / "terminal").exists()


@pytest.mark.asyncio
async def test_compact_runtime_anchor_mismatch_fails_before_any_live_side_effect(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    live, journal, adapter, materializers = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
    )
    live._anchors = replace(live._anchors, compact_runtime_pin_digest="f" * 64)

    with pytest.raises(ValueError, match="Pin verification failed closed"):
        await live.invoke()

    assert journal.recover_pending_cleanup() == ()
    assert adapter.dispatch_calls == 0
    assert materializers == []
    assert events == []
    assert not (tmp_path / "terminal").exists()


@pytest.mark.asyncio
async def test_pre_dispatch_compact_binding_drift_precedes_credentials_and_dispatch(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    live, _journal, adapter, materializers = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
    )
    original = runtime_module.verify_compact_web_analysis_live_pin_binding
    calls = 0

    def verify_then_drift(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("injected compact binding drift")
        return original(*args, **kwargs)

    monkeypatch.setattr(
        runtime_module,
        "verify_compact_web_analysis_live_pin_binding",
        verify_then_drift,
    )

    with pytest.raises(
        CompactSkillBoundWebAnalysisLiveRuntimeError,
        match="immediate pre-dispatch revalidation failed",
    ) as raised:
        await live.invoke()

    assert calls == 2
    assert len(materializers) == 1
    assert "materialize" in events
    assert "attest" in events
    assert "stage" not in events
    assert "revalidate" not in events
    assert "dispatch" not in events
    assert adapter.dispatch_calls == 0
    assert raised.value.terminal_run is not None
    assert raised.value.terminal_run.terminal_claim.dispatch_count == 0


@pytest.mark.asyncio
async def test_authorization_expiring_at_dispatch_marker_never_calls_backend(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    authorization = _signed(
        authorization_context,
        _statement(
            authorization_context,
            expires_at=_NOW + timedelta(seconds=35),
        ),
    )
    live, journal, adapter, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
        signed_authorization=authorization,
    )

    with pytest.raises(
        CompactSkillBoundWebAnalysisLiveRuntimeError,
        match="dispatch marker was uncertain",
    ) as raised:
        await live.invoke()

    assert adapter.dispatch_calls == 0
    assert "dispatch" not in events
    assert raised.value.terminal_run is not None
    assert raised.value.terminal_run.terminal_claim.dispatch_count == 0
    assert raised.value.terminal_run.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.ABANDONED
    )
    durable = journal.inspect(raised.value.terminal_run.terminal_claim.binding.claim_id)
    assert durable == raised.value.terminal_run.terminal_claim
    assert durable is not None and durable.reusable is False


@pytest.mark.parametrize(
    ("stage", "error_factory"),
    [
        ("reservation", lambda: asyncio.CancelledError("reservation cancellation")),
        ("live-start", lambda: SystemExit("live-start process exit")),
        ("materialization", lambda: KeyboardInterrupt("materialization interrupt")),
        (
            "materialization-attestation",
            lambda: DockerPreCleanupBarrierDeadlineExceeded("attestation deadline"),
        ),
        ("pre-dispatch", lambda: asyncio.CancelledError("pre-dispatch cancellation")),
        (
            "dispatch-marker",
            lambda: DockerPreCleanupBarrierDeadlineExceeded("dispatch marker deadline"),
        ),
    ],
)
@pytest.mark.asyncio
async def test_claim_stage_process_control_is_cleanup_bound_and_rethrown_exactly(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    error_factory: Callable[[], BaseException],
) -> None:
    events: list[str] = []
    live, journal, adapter, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
    )
    interruption = error_factory()

    if stage == "reservation":
        original = journal.reserve_with_gate_d_context

        def interrupt_reservation(*args: Any, **kwargs: Any) -> Any:
            original(*args, **kwargs)
            raise interruption

        monkeypatch.setattr(journal, "reserve_with_gate_d_context", interrupt_reservation)
    elif stage == "live-start":
        original = journal.begin_live

        def interrupt_live_start(*args: Any, **kwargs: Any) -> Any:
            original(*args, **kwargs)
            raise interruption

        monkeypatch.setattr(journal, "begin_live", interrupt_live_start)
    elif stage == "materialization":
        original = _FakeMaterializer.materialize

        def interrupt_materialization(self: _FakeMaterializer, *args: Any) -> None:
            original(self, *args)
            raise interruption

        monkeypatch.setattr(_FakeMaterializer, "materialize", interrupt_materialization)
    elif stage == "materialization-attestation":
        original = _FakeMaterializer.live_attestation

        def interrupt_attestation(self: _FakeMaterializer) -> Any:
            original(self)
            raise interruption

        monkeypatch.setattr(_FakeMaterializer, "live_attestation", interrupt_attestation)
    elif stage == "pre-dispatch":
        original = adapter.stage_one_call

        def interrupt_pre_dispatch(*args: Any, **kwargs: Any) -> None:
            original(*args, **kwargs)
            raise interruption

        monkeypatch.setattr(adapter, "stage_one_call", interrupt_pre_dispatch)
    else:
        original = journal.mark_dispatch_started

        def interrupt_marker(*args: Any, **kwargs: Any) -> Any:
            original(*args, **kwargs)
            raise interruption

        monkeypatch.setattr(journal, "mark_dispatch_started", interrupt_marker)

    with pytest.raises(type(interruption)) as raised:
        await live.invoke()

    assert raised.value is interruption
    assert adapter.dispatch_calls == 0
    assert "dispatch" not in events
    trust_anchor = authorization_context.trust_anchor
    authorization = WebAnalysisOneCallAuthorizationVerifierV2(
        trust_anchor=trust_anchor,
        expected_trust_anchor_digest=trust_anchor.digest,
        clock=lambda: _NOW + timedelta(seconds=30),
    ).verify(
        _signed(authorization_context, _statement(authorization_context)),
        admission=authorization_context.admission,
        live_request=authorization_context.live_request,
        capacity_pin=authorization_context.capacity_pin,
        lineage_transport_pin=authorization_context.transport_pin,
        compact_runtime_pin=authorization_context.compact_runtime,
        compact_transport_pin=authorization_context.compact_transport,
    )
    binding = build_web_analysis_live_claim_binding(
        admission=authorization_context.admission,
        authorization=authorization.coordinate,
    )
    durable = journal.inspect(binding.claim_id)
    assert durable is not None
    assert durable.phase is WebAnalysisLiveClaimPhase.TERMINAL
    assert durable.reusable is False
    assert durable.terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.ABANDONED
    assert durable.dispatch_count == (1 if stage == "dispatch-marker" else 0)


@pytest.mark.asyncio
async def test_reservation_recovery_process_control_is_not_wrapped(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live, journal, adapter, _ = _build_runtime(authorization_context, tmp_path)
    original_reserve = journal.reserve_with_gate_d_context
    interruption = SystemExit("injected reservation recovery process exit")

    def commit_then_fail(*args: Any, **kwargs: Any) -> Any:
        original_reserve(*args, **kwargs)
        raise WebAnalysisLiveClaimJournalError("injected reservation acknowledgement loss")

    def interrupt_recovery(*_args: Any, **_kwargs: Any) -> Any:
        raise interruption

    monkeypatch.setattr(journal, "reserve_with_gate_d_context", commit_then_fail)
    monkeypatch.setattr(journal, "recover_binding_pending_cleanup", interrupt_recovery)

    with pytest.raises(SystemExit) as raised:
        await live.invoke()

    assert raised.value is interruption
    assert adapter.dispatch_calls == 0
    assert adapter._binding is None


@pytest.mark.asyncio
async def test_pre_dispatch_cleanup_transition_process_control_wins_over_original_failure(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live, journal, adapter, _ = _build_runtime(authorization_context, tmp_path)
    interruption = KeyboardInterrupt("injected pending transition interrupt")

    def ordinary_pre_dispatch_failure(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("injected ordinary staging failure")

    def interrupt_pending(*_args: Any, **_kwargs: Any) -> Any:
        raise interruption

    monkeypatch.setattr(adapter, "stage_one_call", ordinary_pre_dispatch_failure)
    monkeypatch.setattr(journal, "mark_pending_cleanup", interrupt_pending)

    with pytest.raises(KeyboardInterrupt) as raised:
        await live.invoke()

    assert raised.value is interruption
    assert adapter.dispatch_calls == 0
    assert adapter._binding is not None
    durable = journal.inspect(adapter._binding.claim_id)
    assert durable is not None
    assert durable.phase is WebAnalysisLiveClaimPhase.TERMINAL
    assert durable.terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.ABANDONED


@pytest.mark.parametrize("boundary", ["failure-settlement", "model-cleanup"])
@pytest.mark.asyncio
async def test_failure_cleanup_boundary_process_control_is_not_converted(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    events: list[str] = []
    live, journal, adapter, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
    )
    interruption: BaseException = (
        SystemExit("injected failure settlement exit")
        if boundary == "failure-settlement"
        else asyncio.CancelledError("injected model cleanup cancellation")
    )

    def ordinary_pre_dispatch_failure(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("injected ordinary pre-dispatch failure")

    def interrupt(*_args: Any, **_kwargs: Any) -> Any:
        raise interruption

    monkeypatch.setattr(adapter, "stage_one_call", ordinary_pre_dispatch_failure)
    if boundary == "failure-settlement":
        monkeypatch.setattr(adapter, "settle_without_dispatch", interrupt)
    else:
        monkeypatch.setattr(
            _FakeMaterializer,
            "cleanup_owned_resources_and_verify_absent",
            interrupt,
        )

    with pytest.raises(type(interruption)) as raised:
        await live.invoke()

    assert raised.value is interruption
    assert adapter.dispatch_calls == 0
    assert adapter._binding is not None
    durable = journal.inspect(adapter._binding.claim_id)
    assert durable is not None
    assert durable.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert durable.reusable is False


@pytest.mark.asyncio
async def test_final_view_failure_precedes_marker_and_dispatch(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    live, _, adapter, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
        reattest_fails=True,
    )

    with pytest.raises(
        CompactSkillBoundWebAnalysisLiveRuntimeError,
        match="pre-dispatch revalidation failed",
    ) as raised:
        await live.invoke()

    assert adapter.dispatch_calls == 0
    assert "dispatch" not in events
    assert raised.value.terminal_run is not None
    assert raised.value.terminal_run.terminal_claim.dispatch_count == 0
    assert raised.value.terminal_run.terminal_claim.pending_outcome is (
        WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED
    )
    assert events.index("prepared-context") < events.index("route-reattest")
    assert events.index("route-reattest") < events.index("settle-without-dispatch")


@pytest.mark.parametrize("route_mode", ("missing", "tampered", "no-alias", "foreign-member"))
@pytest.mark.asyncio
async def test_provider_route_evidence_failure_is_pre_marker_and_never_dispatches(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    route_mode: str,
) -> None:
    events: list[str] = []
    live, _, adapter, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
        route_mode=route_mode,
    )

    with pytest.raises(
        CompactSkillBoundWebAnalysisLiveRuntimeError,
        match="pre-dispatch revalidation failed",
    ) as raised:
        await live.invoke()

    assert adapter.dispatch_calls == 0
    assert "dispatch-marker" not in events
    assert "dispatch" not in events
    assert raised.value.terminal_run is not None
    receipt = raised.value.terminal_run.receipt
    assert receipt.failure_stage == "pre-dispatch-revalidation"
    assert receipt.pending_claim.dispatch_count == 0
    assert receipt.provider_route_attestation is None
    assert receipt.cleanup_result.provider_route_attestation_digest is None


@pytest.mark.parametrize(
    "binding_mode",
    ("foreign-self-consistent", "zero-lease", "foreign-lease"),
)
@pytest.mark.asyncio
async def test_self_consistent_foreign_transport_binding_is_rejected_before_marker(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    binding_mode: str,
) -> None:
    events: list[str] = []
    live, journal, adapter, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
        binding_mode=binding_mode,
    )

    with pytest.raises(
        CompactSkillBoundWebAnalysisLiveRuntimeError,
        match="pre-dispatch revalidation failed",
    ) as raised:
        await live.invoke()

    assert adapter.dispatch_calls == 0
    assert "dispatch-marker" not in events
    assert "dispatch" not in events
    terminal = raised.value.terminal_run
    assert terminal is not None
    assert terminal.terminal_claim.dispatch_count == 0
    assert terminal.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.ABANDONED
    )
    assert terminal.receipt.failure_stage == "pre-dispatch-revalidation"
    durable = journal.inspect(terminal.terminal_claim.binding.claim_id)
    assert durable == terminal.terminal_claim
    assert durable is not None and durable.reusable is False


@pytest.mark.asyncio
async def test_transport_cleanup_failure_leaves_nonreusable_pending_and_no_receipt(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    adapter = _FakeDispatchAdapter(
        authorization_context,
        events,
        cleanup_blocks=True,
    )
    live, journal, _, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
        adapter=adapter,
    )

    with pytest.raises(CompactSkillBoundWebAnalysisCleanupBlockedError) as raised:
        await live.invoke()

    pending = raised.value.pending_claim
    assert pending is not None
    assert journal.inspect(pending.binding.claim_id) == pending
    assert pending.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert pending.pending_outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
    assert pending.dispatch_count == 1
    assert pending.reusable is False
    assert adapter.dispatch_calls == 1
    assert "model-cleanup" in events
    assert not (tmp_path / "terminal").exists()


@pytest.mark.asyncio
async def test_model_cleanup_failure_never_seals_or_terminalizes_success(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    live, journal, adapter, _ = _build_runtime(
        authorization_context,
        tmp_path,
        cleanup_fails=True,
    )

    with pytest.raises(CompactSkillBoundWebAnalysisCleanupBlockedError) as raised:
        await live.invoke()

    pending = raised.value.pending_claim
    assert pending is not None
    assert journal.inspect(pending.binding.claim_id) == pending
    assert pending.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert pending.dispatch_count == 1
    assert adapter.dispatch_calls == 1
    assert not (tmp_path / "terminal").exists()


@pytest.mark.asyncio
async def test_post_success_model_cleanup_process_control_is_preserved_without_proposal(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live, journal, adapter, _ = _build_runtime(authorization_context, tmp_path)
    interruption = DockerPreCleanupBarrierDeadlineExceeded(
        "injected post-success model cleanup deadline"
    )

    def interrupt_cleanup(*_args: Any, **_kwargs: Any) -> Any:
        raise interruption

    monkeypatch.setattr(
        _FakeMaterializer,
        "cleanup_owned_resources_and_verify_absent",
        interrupt_cleanup,
    )

    with pytest.raises(DockerPreCleanupBarrierDeadlineExceeded) as raised:
        await live.invoke()

    assert raised.value is interruption
    assert adapter.dispatch_calls == 1
    assert adapter._binding is not None
    durable = journal.inspect(adapter._binding.claim_id)
    assert durable is not None
    assert durable.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert durable.pending_outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
    assert durable.dispatch_count == 1
    assert durable.reusable is False
    assert journal.inspect_terminal_publication(adapter._binding.claim_id) is None


@pytest.mark.parametrize(
    "interruption_kind",
    ("deadline", "cancelled", "system-exit", "keyboard-interrupt", "barrier"),
)
@pytest.mark.parametrize(
    "secondary_boundary",
    ("model-cleanup", "publication", "strict-loader"),
)
@pytest.mark.asyncio
async def test_interrupted_dispatch_original_priority_survives_secondary_failure(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption_kind: str,
    secondary_boundary: str,
) -> None:
    live, journal, adapter, _ = _build_runtime(authorization_context, tmp_path)
    if interruption_kind == "deadline":
        interruption: BaseException = DockerPreCleanupBarrierDeadlineExceeded(
            "injected dispatch deadline"
        )
    elif interruption_kind == "cancelled":
        interruption = asyncio.CancelledError("injected dispatch cancellation")
    elif interruption_kind == "system-exit":
        interruption = SystemExit("injected dispatch exit")
    elif interruption_kind == "keyboard-interrupt":
        interruption = KeyboardInterrupt("injected dispatch interrupt")
    else:
        interruption = DockerPreCleanupBarrierError(
            cause=RuntimeError("injected dispatch barrier failure")
        )
    original_dispatch = adapter.dispatch_one

    async def interrupted_dispatch(*args: Any, **kwargs: Any) -> Any:
        settlement = await original_dispatch(*args, **kwargs)
        failure_digest = sha256(b"injected interrupted dispatch").hexdigest()
        failed = adapter._settlement(
            settlement.pending_claim,
            cleanup=settlement.transport_cleanup,
            processed=None,
            failure_stage="post-observation-recovery",
            failure_digest=failure_digest,
        )
        raise runtime_module._CompactLiveDispatchInterrupted(failed, interruption)

    monkeypatch.setattr(adapter, "dispatch_one", interrupted_dispatch)
    if secondary_boundary == "model-cleanup":

        def fail_model_cleanup(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("injected secondary model cleanup failure")

        monkeypatch.setattr(
            _FakeMaterializer,
            "cleanup_owned_resources_and_verify_absent",
            fail_model_cleanup,
        )
    elif secondary_boundary == "publication":

        def fail_publication(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("injected secondary publication failure")

        monkeypatch.setattr(
            runtime_module,
            "publish_compact_skill_bound_web_analysis_terminal_run",
            fail_publication,
        )
    else:

        def fail_strict_loader(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("injected secondary strict-loader failure")

        monkeypatch.setattr(
            runtime_module,
            "load_verified_compact_skill_bound_web_analysis_terminal_publication_candidate",
            fail_strict_loader,
        )

    with pytest.raises(type(interruption)) as raised:
        await live.invoke()

    assert raised.value is interruption
    assert adapter.dispatch_calls == 1
    assert adapter._binding is not None
    durable = journal.inspect(adapter._binding.claim_id)
    assert durable is not None
    assert durable.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert durable.reusable is False
    publication = journal.inspect_terminal_publication(adapter._binding.claim_id)
    assert publication is None or publication.root_digest is None


@pytest.mark.parametrize("symlink_component", ("output-root", "ancestor"))
@pytest.mark.asyncio
async def test_preexisting_terminal_root_symlink_is_rejected_before_intent_or_write(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    symlink_component: str,
) -> None:
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
    live, journal, adapter, _ = _build_runtime(
        authorization_context,
        tmp_path / "runtime",
        terminal_output_root=output_root,
    )

    with pytest.raises(ValueError, match="symlink component"):
        await live.invoke()

    assert adapter.dispatch_calls == 1
    assert adapter._binding is not None
    pending = journal.inspect(adapter._binding.claim_id)
    assert pending is not None
    assert pending.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert pending.reusable is False
    assert journal.inspect_terminal_publication(adapter._binding.claim_id) is None
    assert tuple(relocated.iterdir()) == ()


@pytest.mark.asyncio
async def test_dispatch_marker_commit_uncertainty_never_calls_fake_dispatch(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    live, journal, adapter, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
    )
    original = journal.mark_dispatch_started

    def commit_then_raise(handle: Any) -> Any:
        original(handle)
        raise RuntimeError("injected marker acknowledgement loss")

    monkeypatch.setattr(journal, "mark_dispatch_started", commit_then_raise)
    with pytest.raises(
        CompactSkillBoundWebAnalysisLiveRuntimeError,
        match="dispatch marker was uncertain",
    ) as raised:
        await live.invoke()

    assert adapter.dispatch_calls == 0
    assert "dispatch" not in events
    assert raised.value.terminal_run is not None
    assert raised.value.terminal_run.receipt.pending_claim.pending_outcome is (
        WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN
    )
    assert raised.value.terminal_run.terminal_claim.dispatch_count == 1
    assert raised.value.terminal_run.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.ABANDONED
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("dispatch_mode", ["raise", "cancel"])
async def test_dispatch_uncertainty_consumes_one_slot_without_retry(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    dispatch_mode: str,
) -> None:
    events: list[str] = []
    adapter = _FakeDispatchAdapter(
        authorization_context,
        events,
        dispatch_mode=dispatch_mode,
    )
    live, journal, _, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
        adapter=adapter,
    )

    terminal_run = None
    if dispatch_mode == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await live.invoke()
    else:
        with pytest.raises(
            CompactSkillBoundWebAnalysisLiveRuntimeError,
            match="dispatch failed without redispatch",
        ) as raised:
            await live.invoke()
        terminal_run = raised.value.terminal_run

    assert adapter.dispatch_calls == 1
    assert events.count("dispatch") == 1
    if terminal_run is None:
        assert adapter._binding is not None
        durable = journal.inspect(adapter._binding.claim_id)
        assert durable is not None
        assert durable.phase is WebAnalysisLiveClaimPhase.TERMINAL
        assert durable.dispatch_count == 1
        assert durable.terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.ABANDONED
        publication = journal.inspect_terminal_publication(adapter._binding.claim_id)
        assert publication is not None and publication.root_digest is not None
    else:
        assert terminal_run.receipt.pending_claim.pending_outcome is (
            WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN
        )
        assert terminal_run.terminal_claim.dispatch_count == 1
        assert terminal_run.terminal_claim.terminal_disposition is (
            WebAnalysisLiveClaimTerminalDisposition.ABANDONED
        )
        assert terminal_run.retry_authority is False
        assert terminal_run.automatic_redispatch_authority is False


@pytest.mark.asyncio
async def test_invalid_response_becomes_failure_terminal_without_proposal(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    adapter = _FakeDispatchAdapter(
        authorization_context,
        events,
        dispatch_mode="invalid-response",
    )
    live, _, _, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
        adapter=adapter,
    )

    with pytest.raises(
        CompactSkillBoundWebAnalysisLiveRuntimeError,
        match="ended without a successful proposal",
    ) as raised:
        await live.invoke()

    assert adapter.dispatch_calls == 1
    assert raised.value.terminal_run is not None
    assert raised.value.terminal_run.proposal is None
    assert raised.value.terminal_run.receipt.failure_stage == "response-validation"
    assert raised.value.terminal_run.receipt.pending_claim.pending_outcome is (
        WebAnalysisLiveClaimPendingOutcome.FAILURE_OBSERVED
    )
    assert raised.value.terminal_run.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.FAILURE
    )


def _make_pending_success(
    context: SimpleNamespace,
    journal: WebAnalysisLiveClaimJournal,
    adapter: _FakeDispatchAdapter,
) -> WebAnalysisLiveClaimJournalEntry:
    trust_anchor = context.trust_anchor
    initial = WebAnalysisOneCallAuthorizationVerifierV2(
        trust_anchor=trust_anchor,
        expected_trust_anchor_digest=trust_anchor.digest,
        clock=lambda: _NOW + timedelta(seconds=30),
    ).verify(
        _signed(context, _statement(context)),
        admission=context.admission,
        live_request=context.live_request,
        capacity_pin=context.capacity_pin,
        lineage_transport_pin=context.transport_pin,
        compact_runtime_pin=context.compact_runtime,
        compact_transport_pin=context.compact_transport,
    )
    before_dispatch = WebAnalysisOneCallAuthorizationVerifierV2(
        trust_anchor=trust_anchor,
        expected_trust_anchor_digest=trust_anchor.digest,
        clock=lambda: _NOW + timedelta(seconds=34),
    ).verify(
        _signed(context, _statement(context)),
        admission=context.admission,
        live_request=context.live_request,
        capacity_pin=context.capacity_pin,
        lineage_transport_pin=context.transport_pin,
        compact_runtime_pin=context.compact_runtime,
        compact_transport_pin=context.compact_transport,
    )
    binding = build_web_analysis_live_claim_binding(
        admission=context.admission,
        authorization=initial.coordinate,
    )
    reserved = journal.reserve_with_gate_d_context(
        binding,
        initial_authorization_verification_digest=initial.verification_digest,
        initial_authorization_evaluated_at=initial.evaluated_at,
        initial_authorization_expires_at=initial.expires_at,
    )
    started = journal.begin_live(reserved)
    prepared = adapter.prepare(
        binding=binding,
        journal=journal,
        registration=context.live_request.provider_registration,
        chat=context.live_request.chat_request,
        result_processor=lambda _result: (_ for _ in ()).throw(
            AssertionError("recovery must not process a new result")
        ),
    )
    adapter.stage_one_call(prepared)
    adapter.revalidate_prepared(prepared)
    transport = adapter.prepared_context(prepared).transport_binding
    started = journal.record_gate_d_pre_dispatch_context(
        started,
        pre_dispatch_authorization_verification_digest=(before_dispatch.verification_digest),
        pre_dispatch_authorization_evaluated_at=before_dispatch.evaluated_at,
        pre_dispatch_authorization_expires_at=before_dispatch.expires_at,
        provider_route_attestation_digest=sha256(b"recovery provider route").hexdigest(),
        transport_execution_id=transport.transport_execution_id,
        lease_ids=transport.lease_ids,
        worker_context_digest=transport.worker_context_digest,
        job_metadata_digest=transport.job_metadata_digest,
        transport_binding_digest=transport.binding_digest,
    )
    dispatch = journal.mark_dispatch_started(started)
    return journal.mark_pending_cleanup(
        dispatch,
        outcome=WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED,
    )


def _product_pending_with_issued_lease(
    context: SimpleNamespace,
    tmp_path: Path,
    *,
    with_pre_dispatch_context: bool,
    materialize_lease: bool = True,
) -> SimpleNamespace:
    base = _NOW + timedelta(seconds=30)
    journal = WebAnalysisLiveClaimJournal(
        tmp_path / "claim.sqlite3",
        allow_create=True,
        clock=_AdvancingClock(
            base + timedelta(seconds=1),
            base + timedelta(seconds=2),
            base + timedelta(seconds=5),
            base + timedelta(seconds=6),
            base + timedelta(seconds=7),
        ),
    )
    trust_anchor = context.trust_anchor
    bundle = _signed(context, _statement(context))
    initial = WebAnalysisOneCallAuthorizationVerifierV2(
        trust_anchor=trust_anchor,
        expected_trust_anchor_digest=trust_anchor.digest,
        clock=lambda: base,
    ).verify(
        bundle,
        admission=context.admission,
        live_request=context.live_request,
        capacity_pin=context.capacity_pin,
        lineage_transport_pin=context.transport_pin,
        compact_runtime_pin=context.compact_runtime,
        compact_transport_pin=context.compact_transport,
    )
    before = WebAnalysisOneCallAuthorizationVerifierV2(
        trust_anchor=trust_anchor,
        expected_trust_anchor_digest=trust_anchor.digest,
        clock=lambda: base + timedelta(seconds=4),
    ).verify(
        bundle,
        admission=context.admission,
        live_request=context.live_request,
        capacity_pin=context.capacity_pin,
        lineage_transport_pin=context.transport_pin,
        compact_runtime_pin=context.compact_runtime,
        compact_transport_pin=context.compact_transport,
    )
    binding = build_web_analysis_live_claim_binding(
        admission=context.admission,
        authorization=initial.coordinate,
    )
    reserved = journal.reserve_with_gate_d_context(
        binding,
        initial_authorization_verification_digest=initial.verification_digest,
        initial_authorization_evaluated_at=initial.evaluated_at,
        initial_authorization_expires_at=initial.expires_at,
    )
    started = journal.begin_live(reserved)
    broker = SecretBroker(clock=lambda: base + timedelta(seconds=4))
    registration = context.live_request.provider_registration
    broker.register(registration.secret_ref, "fake-local-provider-token-for-runtime-test")
    first = DockerCompactSkillBoundWebAnalysisDispatchAdapter(
        capacity_pin=context.capacity_pin,
        live_request=context.live_request,
        lineage_transport_pin=context.transport_pin,
        compact_runtime_pin=context.compact_runtime,
        compact_transport_pin=context.compact_transport,
        expected_capacity_pin_digest=context.capacity_pin.pin_digest,
        expected_lineage_transport_pin_digest=context.transport_pin.pin_digest,
        expected_compact_runtime_pin_digest=context.compact_runtime.pin_digest,
        expected_compact_transport_pin_digest=context.compact_transport.pin_digest,
        secrets=broker,
        docker_executable="docker",
    )
    prepared = first.prepare(
        binding=binding,
        journal=journal,
        registration=registration,
        chat=context.live_request.chat_request,
        result_processor=lambda _result: (_ for _ in ()).throw(
            AssertionError("recovery setup must not process a Worker result")
        ),
    )
    if materialize_lease:
        first.stage_one_call(prepared)
        first.revalidate_prepared(prepared)
        transport = first.prepared_context(prepared).transport_binding
    else:
        if with_pre_dispatch_context:
            raise AssertionError("an unmaterialized lease cannot have durable transport context")
        secret_request = prepared.job.secret_requests[0]
        lease_id = runtime_module._deterministic_lease_id(
            claim_digest=binding.claim_digest,
            secret_ref=secret_request.secret_ref,
            binding=secret_request.binding,
        )
        broker.issue_exact(
            secret_request.secret_ref,
            lease_id=lease_id,
            audience=f"{prepared.request.agent_id}:{prepared.execution_id}",
            binding=secret_request.binding,
            scope=f"claim:{binding.claim_digest}",
            ttl_seconds=secret_request.ttl_seconds,
            max_uses=1,
        )
        transport = SimpleNamespace(lease_ids=(lease_id,))
    if with_pre_dispatch_context:
        started = journal.record_gate_d_pre_dispatch_context(
            started,
            pre_dispatch_authorization_verification_digest=before.verification_digest,
            pre_dispatch_authorization_evaluated_at=before.evaluated_at,
            pre_dispatch_authorization_expires_at=before.expires_at,
            provider_route_attestation_digest=sha256(
                b"product recovery provider route"
            ).hexdigest(),
            transport_execution_id=transport.transport_execution_id,
            lease_ids=transport.lease_ids,
            worker_context_digest=transport.worker_context_digest,
            job_metadata_digest=transport.job_metadata_digest,
            transport_binding_digest=transport.binding_digest,
        )
    pending = journal.mark_pending_cleanup(
        started,
        outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
    )
    return SimpleNamespace(
        journal=journal,
        broker=broker,
        binding=binding,
        pending=pending,
        transport=transport,
        registration=registration,
    )


def _production_recovery_adapter(
    context: SimpleNamespace,
    built: SimpleNamespace,
    broker: SecretBroker,
) -> tuple[
    DockerCompactSkillBoundWebAnalysisDispatchAdapter,
    CompactSkillBoundWebAnalysisPreparedDispatch,
]:
    adapter = DockerCompactSkillBoundWebAnalysisDispatchAdapter(
        capacity_pin=context.capacity_pin,
        live_request=context.live_request,
        lineage_transport_pin=context.transport_pin,
        compact_runtime_pin=context.compact_runtime,
        compact_transport_pin=context.compact_transport,
        expected_capacity_pin_digest=context.capacity_pin.pin_digest,
        expected_lineage_transport_pin_digest=context.transport_pin.pin_digest,
        expected_compact_runtime_pin_digest=context.compact_runtime.pin_digest,
        expected_compact_transport_pin_digest=context.compact_transport.pin_digest,
        secrets=broker,
        docker_executable="docker",
    )
    prepared = adapter.prepare(
        binding=built.binding,
        journal=built.journal,
        registration=built.registration,
        chat=context.live_request.chat_request,
        result_processor=lambda _result: (_ for _ in ()).throw(
            AssertionError("quiescent recovery must not process a Worker result")
        ),
    )
    return adapter, prepared


def _patch_transport_cleanup_success(
    monkeypatch: pytest.MonkeyPatch,
    context: SimpleNamespace,
) -> None:
    def cleanup(**kwargs: Any) -> WebAnalysisTransportCleanupProof:
        return WebAnalysisTransportCleanupProof(
            executionId=cast(str, kwargs["execution_id"]),
            transportPinDigest=context.compact_transport.pin_digest,
            externalNetwork=cast(str, kwargs["external_network"]),
            observedResources=(),
        )

    monkeypatch.setattr(
        runtime_module,
        "cleanup_compact_web_analysis_transport_resources",
        cleanup,
    )


def _product_worker_success(
    context: SimpleNamespace,
    registration: ProviderRegistration,
    job: WorkerJob,
) -> WorkerResult:
    draft_wire = canonical_json_bytes(
        _successor_draft_payload(context.skill_run),
        label="product adapter fake compact live draft",
    )
    provider = ProviderChatResult(
        provider_id=registration.provider_id,
        response_id="fake-product-response-1",
        model=registration.model,
        content=draft_wire.decode("utf-8"),
        refusal=None,
        finish_reason="stop",
        tool_calls=[],
        usage=None,
        streamed=False,
        chunks=1,
        target=str(registration.endpoint),
    )
    now = _NOW + timedelta(seconds=35)
    return WorkerResult(
        execution_id=job.execution_id,
        backend="docker",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=provider.model_dump_json(),
        network_log="host-owned fake proxy transcript",
        started_at=now,
        finished_at=now,
    )


def _build_product_live_runtime(
    context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> SimpleNamespace:
    broker = SecretBroker(clock=lambda: _NOW + timedelta(seconds=34))
    registration = context.live_request.provider_registration
    broker.register(registration.secret_ref, "fake-live-provider-token-for-runtime-test")
    adapter = DockerCompactSkillBoundWebAnalysisDispatchAdapter(
        capacity_pin=context.capacity_pin,
        live_request=context.live_request,
        lineage_transport_pin=context.transport_pin,
        compact_runtime_pin=context.compact_runtime,
        compact_transport_pin=context.compact_transport,
        expected_capacity_pin_digest=context.capacity_pin.pin_digest,
        expected_lineage_transport_pin_digest=context.transport_pin.pin_digest,
        expected_compact_runtime_pin_digest=context.compact_runtime.pin_digest,
        expected_compact_transport_pin_digest=context.compact_transport.pin_digest,
        secrets=broker,
        docker_executable="docker",
    )
    _patch_transport_cleanup_success(monkeypatch, context)
    events: list[str] = []
    live, journal, _, materializers = _build_runtime(
        context,
        tmp_path,
        events=events,
        adapter=cast(Any, adapter),
    )
    return SimpleNamespace(
        live=live,
        journal=journal,
        adapter=adapter,
        registration=registration,
        materializers=materializers,
        events=events,
    )


@pytest.mark.asyncio
async def test_issue_exact_post_store_interruption_revokes_recovery_lease_before_terminal(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = SecretBroker(clock=lambda: _NOW + timedelta(seconds=34))
    registration = authorization_context.live_request.provider_registration
    broker.register(registration.secret_ref, "fake-live-provider-token-for-runtime-test")
    adapter = DockerCompactSkillBoundWebAnalysisDispatchAdapter(
        capacity_pin=authorization_context.capacity_pin,
        live_request=authorization_context.live_request,
        lineage_transport_pin=authorization_context.transport_pin,
        compact_runtime_pin=authorization_context.compact_runtime,
        compact_transport_pin=authorization_context.compact_transport,
        expected_capacity_pin_digest=authorization_context.capacity_pin.pin_digest,
        expected_lineage_transport_pin_digest=authorization_context.transport_pin.pin_digest,
        expected_compact_runtime_pin_digest=authorization_context.compact_runtime.pin_digest,
        expected_compact_transport_pin_digest=authorization_context.compact_transport.pin_digest,
        secrets=broker,
        docker_executable="docker",
    )
    _patch_transport_cleanup_success(monkeypatch, authorization_context)
    original_issue_exact = broker.issue_exact
    stored_lease_ids: list[str] = []

    def store_then_interrupt(*args: Any, **kwargs: Any) -> Any:
        lease = original_issue_exact(*args, **kwargs)
        stored_lease_ids.append(lease.lease_id)
        raise RuntimeError("injected interruption after exact lease storage")

    async def unexpected_dispatch(*_args: Any, **_kwargs: Any) -> WorkerResult:
        raise AssertionError("post-issue staging interruption must not dispatch")

    monkeypatch.setattr(broker, "issue_exact", store_then_interrupt)
    monkeypatch.setattr(DockerWorkerBackend, "run", unexpected_dispatch)
    live, journal, _, _ = _build_runtime(
        authorization_context,
        tmp_path,
        adapter=cast(Any, adapter),
    )

    with pytest.raises(
        CompactSkillBoundWebAnalysisLiveRuntimeError,
        match="immediate pre-dispatch revalidation failed",
    ) as raised:
        await live.invoke()

    assert len(stored_lease_ids) == 1
    terminal_run = raised.value.terminal_run
    assert terminal_run is not None
    assert terminal_run.proposal is None
    assert terminal_run.terminal_claim.dispatch_count == 0
    assert terminal_run.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.ABANDONED
    )
    assert terminal_run.receipt.cleanup_result.revoked_lease_ids == tuple(stored_lease_ids)
    prepared_state = cast(Any, adapter)._prepared
    assert prepared_state is not None
    observed = broker.inspect(
        stored_lease_ids[0],
        audience=prepared_state.audience,
        scope=prepared_state.scope,
    )
    assert observed.status is SecretLeaseStatus.REVOKED
    assert observed.remaining_uses == 0
    assert journal.inspect(terminal_run.terminal_claim.binding.claim_id) == (
        terminal_run.terminal_claim
    )


@pytest.mark.asyncio
async def test_product_adapter_processes_raw_result_before_pending_and_cleanup(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = SecretBroker(clock=lambda: _NOW + timedelta(seconds=34))
    registration = authorization_context.live_request.provider_registration
    broker.register(registration.secret_ref, "fake-live-provider-token-for-runtime-test")
    adapter = DockerCompactSkillBoundWebAnalysisDispatchAdapter(
        capacity_pin=authorization_context.capacity_pin,
        live_request=authorization_context.live_request,
        lineage_transport_pin=authorization_context.transport_pin,
        compact_runtime_pin=authorization_context.compact_runtime,
        compact_transport_pin=authorization_context.compact_transport,
        expected_capacity_pin_digest=authorization_context.capacity_pin.pin_digest,
        expected_lineage_transport_pin_digest=authorization_context.transport_pin.pin_digest,
        expected_compact_runtime_pin_digest=authorization_context.compact_runtime.pin_digest,
        expected_compact_transport_pin_digest=authorization_context.compact_transport.pin_digest,
        secrets=broker,
        docker_executable="docker",
    )
    _patch_transport_cleanup_success(monkeypatch, authorization_context)
    backend_calls: list[str] = []

    async def fake_backend_run(
        backend: DockerWorkerBackend,
        job: WorkerJob,
        *,
        secrets: list[Any] | None = None,
    ) -> WorkerResult:
        backend_calls.append(job.execution_id)
        assert secrets is not None and len(secrets) == 1
        draft_wire = canonical_json_bytes(
            _successor_draft_payload(authorization_context.skill_run),
            label="product adapter fake compact live draft",
        )
        provider = ProviderChatResult(
            provider_id=registration.provider_id,
            response_id="fake-product-response-1",
            model=registration.model,
            content=draft_wire.decode("utf-8"),
            refusal=None,
            finish_reason="stop",
            tool_calls=[],
            usage=None,
            streamed=False,
            chunks=1,
            target=str(registration.endpoint),
        )
        now = _NOW + timedelta(seconds=35)
        result = WorkerResult(
            execution_id=job.execution_id,
            backend="docker",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=provider.model_dump_json(),
            network_log="host-owned fake proxy transcript",
            started_at=now,
            finished_at=now,
        )
        await cast(Any, backend)._run_attempt_pre_cleanup_barrier(job, result)
        return result

    monkeypatch.setattr(DockerWorkerBackend, "run", fake_backend_run)
    live, _, _, _ = _build_runtime(
        authorization_context,
        tmp_path,
        adapter=cast(Any, adapter),
    )

    completion = await live.invoke()

    assert len(backend_calls) == 1
    assert completion.terminal_run.receipt.pending_claim.pending_outcome is (
        WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
    )
    assert completion.terminal_run.receipt.cleanup_result.revoked_lease_ids
    assert completion.terminal_run.receipt.cleanup_result.credential_leases_revoked is True
    assert completion.proposal == completion.terminal_run.proposal


@pytest.mark.asyncio
async def test_product_adapter_cancellation_after_success_is_cleanup_bound_and_propagated(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = _build_product_live_runtime(authorization_context, tmp_path, monkeypatch)
    cancellation = asyncio.CancelledError("injected post-success cancellation")
    worker_cleanup: list[str] = []
    backend_calls = 0

    async def fake_backend_run(
        backend: DockerWorkerBackend,
        job: WorkerJob,
        *,
        secrets: list[Any] | None = None,
    ) -> WorkerResult:
        nonlocal backend_calls
        backend_calls += 1
        assert secrets is not None and len(secrets) == 1
        result = _product_worker_success(
            authorization_context,
            built.registration,
            job,
        )
        try:
            await cast(Any, backend)._run_attempt_pre_cleanup_barrier(job, result)
            raise cancellation
        finally:
            worker_cleanup.append(job.execution_id)

    monkeypatch.setattr(DockerWorkerBackend, "run", fake_backend_run)

    with pytest.raises(asyncio.CancelledError) as raised:
        await built.live.invoke()

    assert raised.value is cancellation
    assert backend_calls == 1
    assert len(worker_cleanup) == 1
    assert len(built.materializers) == 1
    assert built.events.count("model-cleanup") == 1
    prepared_state = cast(Any, built.adapter)._prepared
    assert prepared_state is not None
    terminal = built.journal.inspect(prepared_state.binding.claim_id)
    assert terminal is not None
    assert terminal.phase is WebAnalysisLiveClaimPhase.TERMINAL
    assert terminal.pending_outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
    assert terminal.terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.ABANDONED
    publication = built.journal.inspect_terminal_publication(prepared_state.binding.claim_id)
    assert publication is not None and publication.root_digest is not None


@pytest.mark.asyncio
async def test_product_adapter_noncleanup_worker_error_after_success_is_propagated(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = _build_product_live_runtime(authorization_context, tmp_path, monkeypatch)
    worker_error = RuntimeError("injected post-success worker error")
    worker_cleanup: list[str] = []

    async def fake_backend_run(
        backend: DockerWorkerBackend,
        job: WorkerJob,
        *,
        secrets: list[Any] | None = None,
    ) -> WorkerResult:
        assert secrets is not None and len(secrets) == 1
        result = _product_worker_success(
            authorization_context,
            built.registration,
            job,
        )
        try:
            await cast(Any, backend)._run_attempt_pre_cleanup_barrier(job, result)
            raise worker_error
        finally:
            worker_cleanup.append(job.execution_id)

    monkeypatch.setattr(DockerWorkerBackend, "run", fake_backend_run)

    with pytest.raises(RuntimeError) as raised:
        await built.live.invoke()

    assert raised.value is worker_error
    assert len(worker_cleanup) == 1
    prepared_state = cast(Any, built.adapter)._prepared
    assert prepared_state is not None
    terminal = built.journal.inspect(prepared_state.binding.claim_id)
    assert terminal is not None
    assert terminal.pending_outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
    assert terminal.terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.ABANDONED


@pytest.mark.parametrize(
    "worker_error",
    [
        DockerPreCleanupBarrierError(cause=RuntimeError("injected barrier failure")),
        RuntimeError("injected generic worker failure"),
    ],
    ids=("barrier-error", "generic-worker-error"),
)
@pytest.mark.asyncio
async def test_worker_error_survives_initial_transport_cleanup_failure_and_retry(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    worker_error: BaseException,
) -> None:
    built = _build_product_live_runtime(authorization_context, tmp_path, monkeypatch)
    cleanup_calls = 0

    def cleanup(**kwargs: Any) -> WebAnalysisTransportCleanupProof:
        nonlocal cleanup_calls
        cleanup_calls += 1
        if cleanup_calls == 1:
            raise RuntimeError("injected initial transport cleanup failure")
        return WebAnalysisTransportCleanupProof(
            executionId=cast(str, kwargs["execution_id"]),
            transportPinDigest=authorization_context.compact_transport.pin_digest,
            externalNetwork=cast(str, kwargs["external_network"]),
            observedResources=(),
        )

    async def fake_backend_run(
        backend: DockerWorkerBackend,
        job: WorkerJob,
        *,
        secrets: list[Any] | None = None,
    ) -> WorkerResult:
        assert secrets is not None and len(secrets) == 1
        result = _product_worker_success(
            authorization_context,
            built.registration,
            job,
        )
        await cast(Any, backend)._run_attempt_pre_cleanup_barrier(job, result)
        raise worker_error

    monkeypatch.setattr(
        runtime_module,
        "cleanup_compact_web_analysis_transport_resources",
        cleanup,
    )
    monkeypatch.setattr(DockerWorkerBackend, "run", fake_backend_run)

    with pytest.raises(type(worker_error)) as raised:
        await built.live.invoke()

    assert raised.value is worker_error
    assert cleanup_calls == 2
    prepared_state = cast(Any, built.adapter)._prepared
    assert prepared_state is not None
    durable = built.journal.inspect(prepared_state.binding.claim_id)
    assert durable is not None
    assert durable.phase is WebAnalysisLiveClaimPhase.TERMINAL
    assert durable.pending_outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
    assert durable.terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.ABANDONED


@pytest.mark.asyncio
async def test_cleanup_process_control_during_worker_failure_recovery_wins_exactly(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = _build_product_live_runtime(authorization_context, tmp_path, monkeypatch)
    worker_error = RuntimeError("injected ordinary post-success worker error")
    cancellation = asyncio.CancelledError("injected recovery cleanup cancellation")
    cleanup_calls = 0

    def cleanup(**_kwargs: Any) -> WebAnalysisTransportCleanupProof:
        nonlocal cleanup_calls
        cleanup_calls += 1
        if cleanup_calls == 1:
            raise RuntimeError("injected initial transport cleanup failure")
        raise cancellation

    async def fake_backend_run(
        backend: DockerWorkerBackend,
        job: WorkerJob,
        *,
        secrets: list[Any] | None = None,
    ) -> WorkerResult:
        assert secrets is not None and len(secrets) == 1
        result = _product_worker_success(
            authorization_context,
            built.registration,
            job,
        )
        await cast(Any, backend)._run_attempt_pre_cleanup_barrier(job, result)
        raise worker_error

    monkeypatch.setattr(
        runtime_module,
        "cleanup_compact_web_analysis_transport_resources",
        cleanup,
    )
    monkeypatch.setattr(DockerWorkerBackend, "run", fake_backend_run)

    with pytest.raises(asyncio.CancelledError) as raised:
        await built.live.invoke()

    assert raised.value is cancellation
    assert cleanup_calls == 2
    assert built.events.count("model-cleanup") == 1
    prepared_state = cast(Any, built.adapter)._prepared
    assert prepared_state is not None
    durable = built.journal.inspect(prepared_state.binding.claim_id)
    assert durable is not None
    assert durable.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert durable.pending_outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
    assert durable.dispatch_count == 1
    assert durable.reusable is False
    assert built.journal.inspect_terminal_publication(prepared_state.binding.claim_id) is None


@pytest.mark.asyncio
async def test_only_worker_cleanup_error_preserves_processed_success(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = _build_product_live_runtime(authorization_context, tmp_path, monkeypatch)
    cleanup_error = WorkerCleanupError.__new__(WorkerCleanupError)
    RuntimeError.__init__(cleanup_error, "injected worker cleanup acknowledgement failure")

    async def fake_backend_run(
        backend: DockerWorkerBackend,
        job: WorkerJob,
        *,
        secrets: list[Any] | None = None,
    ) -> WorkerResult:
        assert secrets is not None and len(secrets) == 1
        result = _product_worker_success(
            authorization_context,
            built.registration,
            job,
        )
        await cast(Any, backend)._run_attempt_pre_cleanup_barrier(job, result)
        raise cleanup_error

    monkeypatch.setattr(DockerWorkerBackend, "run", fake_backend_run)

    completion = await built.live.invoke()

    assert completion.proposal == completion.terminal_run.proposal
    assert completion.terminal_run.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.SUCCESS
    )


@pytest.mark.asyncio
async def test_deadline_after_pending_success_cas_is_not_swallowed(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = _build_product_live_runtime(authorization_context, tmp_path, monkeypatch)
    original_mark = built.journal.mark_pending_cleanup
    worker_cleanup: list[str] = []
    backend_calls = 0
    deadline_error = DockerPreCleanupBarrierDeadlineExceeded("injected deadline after pending CAS")

    def commit_then_deadline(*args: Any, **kwargs: Any) -> Any:
        original_mark(*args, **kwargs)
        raise deadline_error

    async def fake_backend_run(
        backend: DockerWorkerBackend,
        job: WorkerJob,
        *,
        secrets: list[Any] | None = None,
    ) -> WorkerResult:
        nonlocal backend_calls
        backend_calls += 1
        assert secrets is not None and len(secrets) == 1
        result = _product_worker_success(
            authorization_context,
            built.registration,
            job,
        )
        try:
            await cast(Any, backend)._run_attempt_pre_cleanup_barrier(job, result)
            return result
        finally:
            worker_cleanup.append(job.execution_id)

    monkeypatch.setattr(built.journal, "mark_pending_cleanup", commit_then_deadline)
    monkeypatch.setattr(DockerWorkerBackend, "run", fake_backend_run)

    with pytest.raises(DockerPreCleanupBarrierDeadlineExceeded) as raised:
        await built.live.invoke()

    assert raised.value is deadline_error
    assert backend_calls == 1
    assert len(worker_cleanup) == 1
    prepared_state = cast(Any, built.adapter)._prepared
    assert prepared_state is not None
    terminal = built.journal.inspect(prepared_state.binding.claim_id)
    assert terminal is not None
    assert terminal.dispatch_count == 1
    assert terminal.pending_outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
    assert terminal.terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.ABANDONED


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["interpret", "compile"])
async def test_result_processing_deadline_is_not_reclassified_as_failure_observed(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    built = _build_product_live_runtime(authorization_context, tmp_path, monkeypatch)
    worker_cleanup: list[str] = []
    deadline_error = DockerPreCleanupBarrierDeadlineExceeded(f"injected {stage} deadline")

    def deadline(*_args: Any, **_kwargs: Any) -> Any:
        raise deadline_error

    monkeypatch.setattr(
        runtime_module,
        (
            "interpret_compact_web_analysis_transport_result"
            if stage == "interpret"
            else "compile_skill_bound_web_analysis_proposal"
        ),
        deadline,
    )

    async def fake_backend_run(
        backend: DockerWorkerBackend,
        job: WorkerJob,
        *,
        secrets: list[Any] | None = None,
    ) -> WorkerResult:
        assert secrets is not None and len(secrets) == 1
        result = _product_worker_success(
            authorization_context,
            built.registration,
            job,
        )
        try:
            await cast(Any, backend)._run_attempt_pre_cleanup_barrier(job, result)
            return result
        finally:
            worker_cleanup.append(job.execution_id)

    monkeypatch.setattr(DockerWorkerBackend, "run", fake_backend_run)

    with pytest.raises(DockerPreCleanupBarrierDeadlineExceeded) as raised:
        await built.live.invoke()

    assert raised.value is deadline_error
    assert len(worker_cleanup) == 1
    prepared_state = cast(Any, built.adapter)._prepared
    assert prepared_state is not None
    terminal = built.journal.inspect(prepared_state.binding.claim_id)
    assert terminal is not None
    assert terminal.pending_outcome is WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN
    assert terminal.terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.ABANDONED


@pytest.mark.parametrize("with_pre_dispatch_context", [False, True])
def test_product_recovery_revokes_exact_deterministic_lease_with_same_broker(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    with_pre_dispatch_context: bool,
) -> None:
    built = _product_pending_with_issued_lease(
        authorization_context,
        tmp_path,
        with_pre_dispatch_context=with_pre_dispatch_context,
    )
    _patch_transport_cleanup_success(monkeypatch, authorization_context)
    adapter, prepared = _production_recovery_adapter(
        authorization_context,
        built,
        built.broker,
    )
    if with_pre_dispatch_context:
        adapter.restore_recovery_context(
            prepared,
            lease_ids=built.transport.lease_ids,
            transport_binding_digest=built.transport.binding_digest,
            worker_context_digest=built.transport.worker_context_digest,
            job_metadata_digest=built.transport.job_metadata_digest,
        )
    else:
        adapter.restore_possible_pre_context_recovery(prepared)

    settlement = adapter.settle_recovery(
        prepared,
        pending_claim=built.pending,
        failure_stage="quiescent-recovery",
        failure_digest=sha256(b"test quiescent recovery").hexdigest(),
    )

    assert settlement.revoked_lease_ids == built.transport.lease_ids
    assert len(settlement.revoked_lease_ids) == 1
    assert settlement.transport_binding.lease_ids == settlement.revoked_lease_ids
    assert settlement.pending_claim == built.pending


def test_product_pre_context_recovery_revokes_issued_unmaterialized_lease(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = _product_pending_with_issued_lease(
        authorization_context,
        tmp_path,
        with_pre_dispatch_context=False,
        materialize_lease=False,
    )
    _patch_transport_cleanup_success(monkeypatch, authorization_context)
    adapter, prepared = _production_recovery_adapter(
        authorization_context,
        built,
        built.broker,
    )
    adapter.restore_possible_pre_context_recovery(prepared)

    settlement = adapter.settle_recovery(
        prepared,
        pending_claim=built.pending,
        failure_stage="quiescent-recovery",
        failure_digest=sha256(b"test issue-only recovery").hexdigest(),
    )

    assert settlement.revoked_lease_ids == built.transport.lease_ids
    assert (
        built.broker.inspect(
            settlement.revoked_lease_ids[0],
            audience=f"{prepared.request.agent_id}:{prepared.execution_id}",
            scope=f"claim:{built.binding.claim_digest}",
        ).remaining_uses
        == 0
    )


@pytest.mark.parametrize("with_pre_dispatch_context", [False, True])
def test_product_recovery_with_fresh_broker_keeps_credential_claim_pending(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    with_pre_dispatch_context: bool,
) -> None:
    built = _product_pending_with_issued_lease(
        authorization_context,
        tmp_path,
        with_pre_dispatch_context=with_pre_dispatch_context,
    )
    _patch_transport_cleanup_success(monkeypatch, authorization_context)
    fresh = SecretBroker(clock=lambda: _NOW + timedelta(seconds=34))
    fresh.register(
        built.registration.secret_ref,
        "different-process-local-provider-token-for-runtime-test",
    )
    adapter, prepared = _production_recovery_adapter(
        authorization_context,
        built,
        fresh,
    )
    if with_pre_dispatch_context:
        adapter.restore_recovery_context(
            prepared,
            lease_ids=built.transport.lease_ids,
            transport_binding_digest=built.transport.binding_digest,
            worker_context_digest=built.transport.worker_context_digest,
            job_metadata_digest=built.transport.job_metadata_digest,
        )
    else:
        adapter.restore_possible_pre_context_recovery(prepared)

    with pytest.raises(CompactSkillBoundWebAnalysisCleanupBlockedError) as raised:
        adapter.settle_recovery(
            prepared,
            pending_claim=built.pending,
            failure_stage="quiescent-recovery",
            failure_digest=sha256(b"test quiescent recovery").hexdigest(),
        )

    assert raised.value.pending_claim is not None
    assert raised.value.pending_claim.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert raised.value.pending_claim.reusable is False


@pytest.mark.parametrize("failure", ["lease-revoke", "transport-cleanup"])
def test_product_cleanup_failure_records_pending_and_never_returns_settlement(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    built = _product_pending_with_issued_lease(
        authorization_context,
        tmp_path,
        with_pre_dispatch_context=True,
    )
    _patch_transport_cleanup_success(monkeypatch, authorization_context)
    adapter, prepared = _production_recovery_adapter(
        authorization_context,
        built,
        built.broker,
    )
    adapter.restore_recovery_context(
        prepared,
        lease_ids=built.transport.lease_ids,
        transport_binding_digest=built.transport.binding_digest,
        worker_context_digest=built.transport.worker_context_digest,
        job_metadata_digest=built.transport.job_metadata_digest,
    )
    if failure == "lease-revoke":
        monkeypatch.setattr(
            built.broker,
            "revoke",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("injected lease revoke failure")
            ),
        )
    else:
        monkeypatch.setattr(
            runtime_module,
            "cleanup_compact_web_analysis_transport_resources",
            lambda **_kwargs: (_ for _ in ()).throw(
                RuntimeError("injected transport cleanup failure")
            ),
        )

    with pytest.raises(CompactSkillBoundWebAnalysisCleanupBlockedError) as raised:
        adapter.settle_recovery(
            prepared,
            pending_claim=built.pending,
            failure_stage="quiescent-recovery",
            failure_digest=sha256(b"test quiescent recovery").hexdigest(),
        )

    assert raised.value.pending_claim is not None
    assert raised.value.pending_claim.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert raised.value.pending_claim.reusable is False


@pytest.mark.parametrize("failure", ["lease-revoke", "transport-cleanup"])
@pytest.mark.parametrize(
    "error_factory",
    [
        lambda: DockerPreCleanupBarrierDeadlineExceeded("injected cleanup deadline"),
        lambda: asyncio.CancelledError("injected cleanup cancellation"),
        lambda: SystemExit("injected cleanup process exit"),
        lambda: KeyboardInterrupt("injected cleanup keyboard interrupt"),
    ],
    ids=("deadline", "cancelled", "system-exit", "keyboard-interrupt"),
)
def test_product_cleanup_process_control_identity_is_preserved_and_claim_stays_pending(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    error_factory: Callable[[], BaseException],
) -> None:
    built = _product_pending_with_issued_lease(
        authorization_context,
        tmp_path,
        with_pre_dispatch_context=True,
    )
    _patch_transport_cleanup_success(monkeypatch, authorization_context)
    adapter, prepared = _production_recovery_adapter(
        authorization_context,
        built,
        built.broker,
    )
    adapter.restore_recovery_context(
        prepared,
        lease_ids=built.transport.lease_ids,
        transport_binding_digest=built.transport.binding_digest,
        worker_context_digest=built.transport.worker_context_digest,
        job_metadata_digest=built.transport.job_metadata_digest,
    )
    interruption = error_factory()

    def interrupt(*_args: Any, **_kwargs: Any) -> Any:
        raise interruption

    if failure == "lease-revoke":
        monkeypatch.setattr(built.broker, "revoke", interrupt)
    else:
        monkeypatch.setattr(
            runtime_module,
            "cleanup_compact_web_analysis_transport_resources",
            interrupt,
        )

    with pytest.raises(type(interruption)) as raised:
        adapter.settle_recovery(
            prepared,
            pending_claim=built.pending,
            failure_stage="quiescent-recovery",
            failure_digest=sha256(b"process-control recovery").hexdigest(),
        )

    assert raised.value is interruption
    durable = built.journal.inspect(built.pending.binding.claim_id)
    assert durable is not None
    assert durable.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert durable.reusable is False


def test_quiescent_recovery_never_dispatches_and_downgrades_lost_success_evidence(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    base = _NOW + timedelta(seconds=30)
    journal = WebAnalysisLiveClaimJournal(
        tmp_path / "claim.sqlite3",
        allow_create=True,
        clock=_AdvancingClock(
            base + timedelta(seconds=1),
            base + timedelta(seconds=2),
            base + timedelta(seconds=5),
            base + timedelta(seconds=6),
            base + timedelta(seconds=7),
        ),
    )
    setup_adapter = _FakeDispatchAdapter(authorization_context, [])
    pending = _make_pending_success(authorization_context, journal, setup_adapter)
    events: list[str] = []
    recovery_adapter = _FakeDispatchAdapter(authorization_context, events)
    live, _, _, _ = _build_runtime(
        authorization_context,
        tmp_path,
        events=events,
        journal=journal,
        adapter=recovery_adapter,
    )

    terminal_run = live.recover_pending(pending)

    assert recovery_adapter.dispatch_calls == 0
    assert recovery_adapter.restore_calls == 1
    assert "dispatch" not in events
    assert terminal_run.proposal is None
    assert terminal_run.receipt.pre_dispatch_authorization_verification is not None
    assert terminal_run.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.ABANDONED
    )
    assert terminal_run.terminal_claim.dispatch_count == 1


def test_quiescent_recovery_materializer_process_control_is_rethrown_exactly(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _NOW + timedelta(seconds=30)
    journal = WebAnalysisLiveClaimJournal(
        tmp_path / "claim.sqlite3",
        allow_create=True,
        clock=_AdvancingClock(
            base + timedelta(seconds=1),
            base + timedelta(seconds=2),
            base + timedelta(seconds=5),
            base + timedelta(seconds=6),
            base + timedelta(seconds=7),
        ),
    )
    pending = _make_pending_success(
        authorization_context,
        journal,
        _FakeDispatchAdapter(authorization_context, []),
    )
    recovery_adapter = _FakeDispatchAdapter(authorization_context, [])
    live, _, _, _ = _build_runtime(
        authorization_context,
        tmp_path,
        journal=journal,
        adapter=recovery_adapter,
    )
    interruption = KeyboardInterrupt("injected recovery materializer interrupt")

    def interrupt_materializer(_owner: str) -> Any:
        raise interruption

    monkeypatch.setattr(live, "_materializer_factory", interrupt_materializer)

    with pytest.raises(KeyboardInterrupt) as raised:
        live.recover_pending(pending)

    assert raised.value is interruption
    assert recovery_adapter.dispatch_calls == 0
    durable = journal.inspect(pending.binding.claim_id)
    assert durable is not None
    assert durable.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert durable.reusable is False


@pytest.mark.asyncio
async def test_receipt_seal_crash_recovers_by_finalizing_same_publication_only(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live, journal, first_adapter, _ = _build_runtime(authorization_context, tmp_path)
    original_publish = runtime_module.publish_compact_skill_bound_web_analysis_terminal_run
    publish_count = 0

    def count_publish(*args: Any, **kwargs: Any) -> Any:
        nonlocal publish_count
        publish_count += 1
        return original_publish(*args, **kwargs)

    def fail_finalize(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("injected post-seal terminal CAS failure")

    monkeypatch.setattr(
        runtime_module,
        "publish_compact_skill_bound_web_analysis_terminal_run",
        count_publish,
    )
    monkeypatch.setattr(journal, "finalize_terminal", fail_finalize)
    with pytest.raises(CompactSkillBoundWebAnalysisLiveRuntimeError) as raised:
        await live.invoke()
    pending = raised.value.pending_claim
    assert pending is not None
    assert pending.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert first_adapter.dispatch_calls == 1
    assert publish_count == 1
    sealed_path = compact_skill_bound_web_analysis_terminal_run_path(
        tmp_path / "terminal",
        pending,
    )
    assert sealed_path.is_dir()
    initial_runs = tuple((tmp_path / "terminal").rglob("run_*"))
    durable_publication = journal.inspect_terminal_publication(pending.binding.claim_id)
    assert durable_publication is not None
    assert durable_publication.root_digest is not None
    assert durable_publication.publication_digest is not None

    reopened = WebAnalysisLiveClaimJournal(
        journal.path,
        expected_store_id=journal.store_id,
    )
    recovery_events: list[str] = []
    recovery_adapter = _FakeDispatchAdapter(authorization_context, recovery_events)
    recovery, _, _, materializers = _build_runtime(
        authorization_context,
        tmp_path,
        events=recovery_events,
        journal=reopened,
        adapter=recovery_adapter,
    )
    loaded = recovery.recover_pending(pending)

    assert loaded.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.SUCCESS
    )
    assert loaded.proposal is not None
    assert loaded.run_path == Path(durable_publication.run_path)
    assert loaded.verification.root_digest == durable_publication.root_digest
    assert loaded.receipt.receipt_digest == durable_publication.receipt_digest
    assert recovery_adapter.dispatch_calls == 0
    assert recovery_events == []
    assert materializers == []
    assert publish_count == 1
    assert tuple((tmp_path / "terminal").rglob("run_*")) == initial_runs


@pytest.mark.asyncio
async def test_publication_intent_commit_deadline_is_propagated_without_success(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live, journal, adapter, _ = _build_runtime(authorization_context, tmp_path)
    original_record = journal.record_terminal_publication_intent
    deadline = DockerPreCleanupBarrierDeadlineExceeded(
        "injected deadline after publication intent CAS"
    )

    def commit_then_deadline(*args: Any, **kwargs: Any) -> Any:
        original_record(*args, **kwargs)
        raise deadline

    monkeypatch.setattr(journal, "record_terminal_publication_intent", commit_then_deadline)

    with pytest.raises(DockerPreCleanupBarrierDeadlineExceeded) as raised:
        await live.invoke()

    assert raised.value is deadline
    assert adapter._binding is not None
    pending = journal.inspect(adapter._binding.claim_id)
    assert pending is not None
    assert pending.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert pending.dispatch_count == 1
    publication = journal.inspect_terminal_publication(pending.binding.claim_id)
    assert publication is not None
    assert publication.root_digest is None
    assert publication.publication_digest is None
    assert not Path(publication.run_path).exists()


@pytest.mark.asyncio
async def test_publication_anchor_commit_keyboard_interrupt_is_propagated_and_recoverable(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live, journal, adapter, _ = _build_runtime(authorization_context, tmp_path)
    original_anchor = journal.anchor_terminal_publication
    interruption = KeyboardInterrupt("injected interruption after publication root CAS")

    def commit_then_interrupt(*args: Any, **kwargs: Any) -> Any:
        original_anchor(*args, **kwargs)
        raise interruption

    monkeypatch.setattr(journal, "anchor_terminal_publication", commit_then_interrupt)

    with pytest.raises(KeyboardInterrupt) as raised:
        await live.invoke()

    assert raised.value is interruption
    assert adapter._binding is not None
    pending = journal.inspect(adapter._binding.claim_id)
    assert pending is not None
    assert pending.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    publication = journal.inspect_terminal_publication(pending.binding.claim_id)
    assert publication is not None
    assert publication.root_digest is not None
    assert publication.publication_digest is not None

    reopened = WebAnalysisLiveClaimJournal(
        journal.path,
        expected_store_id=journal.store_id,
    )
    recovery_adapter = _FakeDispatchAdapter(authorization_context, [])
    recovery, _, _, materializers = _build_runtime(
        authorization_context,
        tmp_path,
        journal=reopened,
        adapter=recovery_adapter,
    )
    loaded = recovery.recover_pending(pending)

    assert loaded.proposal is not None
    assert loaded.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.SUCCESS
    )
    assert recovery_adapter.dispatch_calls == 0
    assert materializers == []


@pytest.mark.asyncio
@pytest.mark.parametrize("retry_after_runtime_error", (False, True))
async def test_terminal_commit_cancellation_is_propagated_after_durable_nonreusable_outcome(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    retry_after_runtime_error: bool,
) -> None:
    live, journal, adapter, _ = _build_runtime(authorization_context, tmp_path)
    original_finalize = journal.finalize_terminal
    cancellation = asyncio.CancelledError("injected cancellation after terminal CAS")
    call_count = 0

    def commit_then_cancel(*args: Any, **kwargs: Any) -> Any:
        nonlocal call_count
        call_count += 1
        if retry_after_runtime_error and call_count == 1:
            raise RuntimeError("injected ordinary terminal CAS acknowledgement failure")
        original_finalize(*args, **kwargs)
        raise cancellation

    monkeypatch.setattr(journal, "finalize_terminal", commit_then_cancel)

    with pytest.raises(asyncio.CancelledError) as raised:
        await live.invoke()

    assert raised.value is cancellation
    assert call_count == (2 if retry_after_runtime_error else 1)
    assert adapter._binding is not None
    terminal = journal.inspect(adapter._binding.claim_id)
    assert terminal is not None
    assert terminal.phase is WebAnalysisLiveClaimPhase.TERMINAL
    assert terminal.reusable is False
    assert terminal.dispatch_count == 1
    assert terminal.terminal_disposition is WebAnalysisLiveClaimTerminalDisposition.SUCCESS
    publication = journal.inspect_terminal_publication(terminal.binding.claim_id)
    assert publication is not None
    assert publication.root_digest is not None
    assert publication.publication_digest is not None
    assert Path(publication.run_path).is_dir()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name",
    (
        "record_terminal_publication_intent",
        "anchor_terminal_publication",
        "finalize_terminal",
    ),
)
async def test_ordinary_publication_commit_error_recovers_exact_success(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    live, journal, adapter, _ = _build_runtime(authorization_context, tmp_path)
    original = cast(Callable[..., Any], getattr(journal, method_name))
    call_count = 0

    def commit_then_error(*args: Any, **kwargs: Any) -> Any:
        nonlocal call_count
        call_count += 1
        original(*args, **kwargs)
        raise RuntimeError(f"injected acknowledgement loss after {method_name}")

    monkeypatch.setattr(journal, method_name, commit_then_error)

    completion = await live.invoke()

    assert call_count == 1
    assert adapter.dispatch_calls == 1
    assert completion.proposal == completion.terminal_run.proposal
    assert completion.terminal_run.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.SUCCESS
    )
    assert len(tuple((tmp_path / "terminal").rglob("run_*"))) == 1


@pytest.mark.asyncio
async def test_fresh_runtime_recovers_publication_created_before_root_anchor(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live, journal, first_adapter, _ = _build_runtime(authorization_context, tmp_path)
    original_publish = runtime_module.publish_compact_skill_bound_web_analysis_terminal_run
    publish_count = 0
    process_loss = SystemExit("injected process loss after seal publication")

    def publish_then_lose_process(*args: Any, **kwargs: Any) -> Any:
        nonlocal publish_count
        publish_count += 1
        original_publish(*args, **kwargs)
        raise process_loss

    monkeypatch.setattr(
        runtime_module,
        "publish_compact_skill_bound_web_analysis_terminal_run",
        publish_then_lose_process,
    )
    with pytest.raises(SystemExit) as raised:
        await live.invoke()

    assert raised.value is process_loss
    assert first_adapter._binding is not None
    pending = journal.inspect(first_adapter._binding.claim_id)
    assert pending is not None and pending.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert first_adapter.dispatch_calls == 1
    assert publish_count == 1
    intent = journal.inspect_terminal_publication(pending.binding.claim_id)
    assert intent is not None
    assert intent.root_digest is None
    assert intent.publication_digest is None
    assert Path(intent.run_path).is_dir()

    reopened = WebAnalysisLiveClaimJournal(
        journal.path,
        expected_store_id=journal.store_id,
    )
    recovery_adapter = _FakeDispatchAdapter(authorization_context, [])
    recovery, _, _, materializers = _build_runtime(
        authorization_context,
        tmp_path,
        journal=reopened,
        adapter=recovery_adapter,
    )
    loaded = recovery.recover_pending(pending)

    assert loaded.proposal is not None
    assert loaded.terminal_claim.terminal_disposition is (
        WebAnalysisLiveClaimTerminalDisposition.SUCCESS
    )
    anchored = reopened.inspect_terminal_publication(pending.binding.claim_id)
    assert anchored is not None
    assert anchored.root_digest == loaded.verification.root_digest
    assert anchored.publication_digest is not None
    assert recovery_adapter.dispatch_calls == 0
    assert materializers == []
    assert publish_count == 1


@pytest.mark.asyncio
async def test_intent_without_sealed_run_never_recovers_success(
    authorization_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live, journal, adapter, _ = _build_runtime(authorization_context, tmp_path)
    process_loss = SystemExit("injected process loss before seal publication")

    def fail_before_publish(*_args: Any, **_kwargs: Any) -> Any:
        raise process_loss

    monkeypatch.setattr(
        runtime_module,
        "publish_compact_skill_bound_web_analysis_terminal_run",
        fail_before_publish,
    )
    with pytest.raises(SystemExit) as raised:
        await live.invoke()
    assert raised.value is process_loss
    assert adapter._binding is not None
    pending = journal.inspect(adapter._binding.claim_id)
    assert pending is not None and pending.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert adapter.dispatch_calls == 1
    intent = journal.inspect_terminal_publication(pending.binding.claim_id)
    assert intent is not None and intent.root_digest is None
    assert not Path(intent.run_path).exists()

    reopened = WebAnalysisLiveClaimJournal(
        journal.path,
        expected_store_id=journal.store_id,
    )
    recovery, _, recovery_adapter, _ = _build_runtime(
        authorization_context,
        tmp_path,
        journal=reopened,
    )
    with pytest.raises(
        CompactSkillBoundWebAnalysisLiveRuntimeError,
        match="intent has no sealed Run",
    ):
        recovery.recover_pending(pending)
    durable = reopened.inspect(pending.binding.claim_id)
    assert durable == pending
    assert durable is not None and durable.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP
    assert recovery_adapter.dispatch_calls == 0


def test_runtime_imports_no_legacy_execution_or_receipt_path() -> None:
    source_path = Path(runtime_module.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    referenced_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
            referenced_names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Name):
            referenced_names.add(node.id)
    forbidden_modules = {
        "pajin.benchmark.effectiveness.docker",
        "pajin.web_assessment.analysis_skill_runtime",
        "pajin.web_assessment.analysis_skill_receipts",
        "pajin.web_assessment.analysis_runtime",
        "pajin.web_assessment.analysis_local",
    }
    assert imported.isdisjoint(forbidden_modules)
    assert "LocalModelRuntime" not in referenced_names
    assert "RuntimePin" not in referenced_names
    assert "SignedWebAnalysisOneCallAuthorization" not in referenced_names
    assert "WebAnalysisOneCallAuthorizationVerifier" not in referenced_names
    assert "SkillBoundWebAnalysisInvocationRuntime" not in referenced_names
