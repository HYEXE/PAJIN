from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest
from pajin.providers.models import ProviderChatRequest
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import RunStore, load_verified_run_snapshot, verify_run_integrity
from pajin.tools.gateway import GatewayOutcome, canonical_tool_request_digest
from pajin.web_assessment.analysis_local import LocalWebAnalysisProviderAssembly
from pajin.web_assessment.analysis_runtime import (
    WebAnalysisProviderExecutionContext,
    WebAnalysisProviderRunPublication,
    WebAnalysisRunIntegrityError,
    verify_web_analysis_provider_run_publication,
)
from pajin.web_assessment.analysis_skill_invocation import (
    SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
)
from pajin.web_assessment.analysis_skill_projection import (
    VerifiedWebAnalysisSkillProjectionRun,
    _create_web_analysis_skill_projection_run_with_loader,
)
from pajin.web_assessment.analysis_skill_runtime import (
    SkillBoundWebAnalysisCancelledError,
    SkillBoundWebAnalysisInvocationFailureReceipt,
    SkillBoundWebAnalysisInvocationReceipt,
    SkillBoundWebAnalysisInvocationRuntime,
    SkillBoundWebAnalysisProviderRuntime,
    SkillBoundWebAnalysisRuntimeError,
    bind_skill_bound_web_analysis_provider_runtime,
    load_verified_skill_bound_web_analysis_failure,
    load_verified_skill_bound_web_analysis_invocation,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportRuntimePin,
    expected_web_analysis_provider_worker_context,
)
from pajin.web_assessment.discovery_artifact import (
    VerifiedAuthenticatedDiscoveryRun,
    load_verified_authenticated_discovery,
)
from tests import test_web_analysis_runtime as runtime_test
from tests.test_web_analysis_runtime import (
    StubProviderFinalizer,
    StubWebAnalysisProviderGateway,
    _provider_runtime,
)
from tests.test_web_analysis_skill_invocation import _successor_draft_payload
from tests.test_web_analysis_transport import _transport_pin

_EXPECTED_EXTERNAL_NETWORK = "skill-runtime-test-network"


@dataclass(frozen=True, slots=True)
class _SkillRuntimeCase:
    source: VerifiedAuthenticatedDiscoveryRun
    skill_run: VerifiedWebAnalysisSkillProjectionRun
    transport_pin: WebAnalysisTransportRuntimePin
    gateway: StubWebAnalysisProviderGateway
    provider_runtime: SkillBoundWebAnalysisProviderRuntime


class _BeforeDispatchCancellationGateway(StubWebAnalysisProviderGateway):
    def __init__(self, *, content: str | None, mutation: str | None = None) -> None:
        super().__init__(content=content)
        self.mutation = mutation

    async def execute(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> GatewayOutcome:
        self.calls += 1
        self.requests.append(request.model_copy(deep=True))
        self.campaigns.append(campaign.model_copy(deep=True))
        self.grants.append(grant.model_copy(deep=True))
        self.used_calls.append(used_calls)
        store = self.bound_store
        assert store is not None
        assert self.successor_transport is not None
        registration, _runtime, _transport, _digest = self.successor_transport
        request_digest = canonical_tool_request_digest(request)
        recorded_request_digest = (
            "0" * 64
            if self.mutation in {"request-digest", "coherent-request-digest"}
            else request_digest
        )
        reservation = f"requests/{request.request_id}.json"
        store.write_json_create_only(
            reservation,
            {
                "apiVersion": "pajin.dev/tool-request-reservation/v1",
                "kind": "ToolRequestReservation",
                "requestId": request.request_id,
                "requestSha256": (
                    recorded_request_digest
                    if self.mutation == "coherent-request-digest"
                    else request_digest
                ),
            },
        )
        store.append_event(
            "tool.request_reserved",
            {
                "requestId": request.request_id,
                "requestSha256": recorded_request_digest,
                "reservation": reservation,
            },
        )
        store.append_event(
            "tool.policy_evaluated",
            {
                "requestId": request.request_id,
                "toolId": (
                    "provider.foreign.chat" if self.mutation == "policy-tool" else request.tool_id
                ),
                "allowed": True,
                "policy": "test",
                "reason": "local fixture Provider",
            },
        )
        now = datetime.now(UTC)
        execution_id = "exec_" + "5" * 32
        lease_id = "lease_" + "6" * 32
        self.owned_execution_ids = (execution_id,)
        store.append_event(
            "secret.lease.issued",
            {
                "leaseId": lease_id,
                "scope": "run_20000101T000000Z_00000000"
                if self.mutation == "lease-scope"
                else store.run_id,
                "binding": "provider-api-key",
                "secretRefFingerprint": SecretBroker.fingerprint(registration.secret_ref),
                "expiresAt": now + timedelta(seconds=registration.lease_ttl_seconds),
            },
        )
        store.append_event(
            "secret.lease.revoked",
            {
                "leaseId": lease_id,
                "scope": store.run_id,
                "binding": "provider-api-key",
                "reason": "Worker dispatch cancelled before start",
            },
        )
        store.append_event(
            "tool.rate_reservation_released",
            {
                "requestId": request.request_id,
                "reservationId": "rate-reservation-test",
                "requestCost": 1,
                "reason": "cancelled-before-dispatch",
            },
        )
        store.append_event(
            "worker.cancelled",
            {
                "requestId": request.request_id,
                "executionId": (
                    "exec_" + "7" * 32 if self.mutation == "cancel-execution-id" else execution_id
                ),
                "secretLeasesRevoked": 1,
                "beforeDispatch": True,
            },
        )
        raise asyncio.CancelledError


@pytest.fixture
def runtime_verified_source(tmp_path: Path) -> VerifiedAuthenticatedDiscoveryRun:
    return runtime_test.verified_source.__wrapped__(tmp_path)


def _create_skill_run(
    tmp_path: Path,
    source: VerifiedAuthenticatedDiscoveryRun,
) -> VerifiedWebAnalysisSkillProjectionRun:
    return _create_web_analysis_skill_projection_run_with_loader(
        source=source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        output_root=tmp_path / "skill-projection",
        source_loader=load_verified_authenticated_discovery,
    )


def _successor_content(skill_run: VerifiedWebAnalysisSkillProjectionRun) -> str:
    return canonical_json_bytes(
        _successor_draft_payload(skill_run),
        label="test Skill-bound Web analysis response",
    ).decode("utf-8", errors="strict")


def _build_case(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    content: str | None,
    failure: BaseException | None = None,
    gateway: StubWebAnalysisProviderGateway | None = None,
) -> _SkillRuntimeCase:
    skill_run = _create_skill_run(tmp_path, source)
    gateway = gateway or StubWebAnalysisProviderGateway(content=content, failure=failure)
    base_runtime, _budget, provider_store = _provider_runtime(
        tmp_path,
        sample_campaign,
        source,
        gateway,
    )
    transport = _transport_pin(base_runtime.execution_context.effect_runtime_pin)
    gateway.bind_successor_transport(
        registration=base_runtime.registration,
        runtime=base_runtime.execution_context.effect_runtime_pin,
        transport_pin=transport,
        expected_transport_pin_digest=transport.pin_digest,
    )
    base_context_wire = base_runtime.execution_context.model_dump(
        mode="json",
        by_alias=True,
    )
    base_context_wire["contextId"] = ""
    base_context_wire["contextDigest"] = ""
    stable_context = cast(
        dict[str, object],
        cast(dict[str, object], base_context_wire["toolStableExecutionContext"])["context"],
    )
    stable_context["implementationVersion"] = "pajin.tool-adapter/web-analysis-transport-v2"
    stable_context["webAnalysisTransport"] = transport.model_dump(
        mode="json",
        by_alias=True,
    )
    stable_context["providerWorker"] = expected_web_analysis_provider_worker_context(
        transport,
        external_network=_EXPECTED_EXTERNAL_NETWORK,
    )
    base_context = WebAnalysisProviderExecutionContext.model_validate(base_context_wire)
    base_runtime = replace(
        base_runtime,
        execution_context=base_context,
        finalize_provider_run=StubProviderFinalizer(
            provider_store,
            base_context,
            execution_ids=lambda: gateway.owned_execution_ids,
        ),
    )
    assembly = LocalWebAnalysisProviderAssembly(
        provider_runtime=base_runtime,
        finalizer=cast(Any, object()),
    )
    provider_runtime = bind_skill_bound_web_analysis_provider_runtime(
        assembly,
        transport_pin=transport,
        expected_transport_pin_digest=transport.pin_digest,
        expected_external_network=_EXPECTED_EXTERNAL_NETWORK,
    )
    return _SkillRuntimeCase(
        source=source,
        skill_run=skill_run,
        transport_pin=transport,
        gateway=gateway,
        provider_runtime=provider_runtime,
    )


def _runtime(case: _SkillRuntimeCase) -> SkillBoundWebAnalysisInvocationRuntime:
    return SkillBoundWebAnalysisInvocationRuntime(provider_runtime=case.provider_runtime)


async def _invoke(
    runtime: SkillBoundWebAnalysisInvocationRuntime,
    case: _SkillRuntimeCase,
):
    source = case.source
    run = case.skill_run
    transport = case.transport_pin
    return await runtime.invoke(
        source=source,
        skill_run=run,
        transport_pin=transport,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        expected_skill_run_id=run.verification.run_id,
        expected_skill_root_digest=run.verification.root_digest,
        expected_registry_ref=run.index.registry,
        expected_policy_digest=run.index.selection_policy_digest,
        expected_transport_pin_digest=transport.pin_digest,
    )


def _success_load(case: _SkillRuntimeCase, completion: object):
    publication = completion.publication
    provider_publication = completion.provider_publication
    return load_verified_skill_bound_web_analysis_invocation(
        publication.run_path,
        expected_run_id=publication.run_id,
        expected_root_digest=publication.root_digest,
        source=case.source,
        skill_run=case.skill_run,
        transport_pin=case.transport_pin,
        registration=case.provider_runtime.base_runtime.registration,
        provider_run_path=provider_publication.run_path,
        expected_provider_run_id=provider_publication.run_id,
        expected_provider_root_digest=provider_publication.root_digest,
        expected_provider_execution_context=case.provider_runtime.execution_context,
        expected_source_run_id=case.source.verification.run_id,
        expected_source_root_digest=case.source.verification.root_digest,
        expected_skill_run_id=case.skill_run.verification.run_id,
        expected_skill_root_digest=case.skill_run.verification.root_digest,
        expected_registry_ref=case.skill_run.index.registry,
        expected_policy_digest=case.skill_run.index.selection_policy_digest,
        expected_transport_pin_digest=case.transport_pin.pin_digest,
        expected_external_network=_EXPECTED_EXTERNAL_NETWORK,
    )


def _failure_load(
    case: _SkillRuntimeCase,
    error: SkillBoundWebAnalysisRuntimeError | SkillBoundWebAnalysisCancelledError,
):
    publication = error.publication
    provider_publication = error.provider_publication
    assert publication is not None
    assert provider_publication is not None
    return load_verified_skill_bound_web_analysis_failure(
        publication.run_path,
        expected_run_id=publication.run_id,
        expected_root_digest=publication.root_digest,
        source=case.source,
        skill_run=case.skill_run,
        transport_pin=case.transport_pin,
        registration=case.provider_runtime.base_runtime.registration,
        provider_run_path=provider_publication.run_path,
        expected_provider_run_id=provider_publication.run_id,
        expected_provider_root_digest=provider_publication.root_digest,
        expected_provider_execution_context=case.provider_runtime.execution_context,
        expected_source_run_id=case.source.verification.run_id,
        expected_source_root_digest=case.source.verification.root_digest,
        expected_skill_run_id=case.skill_run.verification.run_id,
        expected_skill_root_digest=case.skill_run.verification.root_digest,
        expected_registry_ref=case.skill_run.index.registry,
        expected_policy_digest=case.skill_run.index.selection_policy_digest,
        expected_transport_pin_digest=case.transport_pin.pin_digest,
        expected_external_network=_EXPECTED_EXTERNAL_NETWORK,
    )


def test_binder_layers_successor_context_over_exact_base_provider_runtime(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    runtime_verified_source: VerifiedAuthenticatedDiscoveryRun,
) -> None:
    case = _build_case(
        tmp_path,
        sample_campaign,
        runtime_verified_source,
        content="{}",
    )

    runtime = case.provider_runtime
    context = runtime.execution_context
    assert context.base_provider_execution_context == runtime.base_runtime.execution_context
    assert context.transport_pin == case.transport_pin
    assert context.provider_id == runtime.base_runtime.registration.provider_id
    assert context.invocation_pin.role == "skill-bound-web-analysis-proposal"
    assert context.secret_material_embedded is False
    assert context.execution_authority is False
    assert runtime.expected_external_network == _EXPECTED_EXTERNAL_NETWORK

    with pytest.raises(SkillBoundWebAnalysisRuntimeError):
        bind_skill_bound_web_analysis_provider_runtime(
            LocalWebAnalysisProviderAssembly(
                provider_runtime=runtime.base_runtime,
                finalizer=cast(Any, object()),
            ),
            transport_pin=case.transport_pin,
            expected_transport_pin_digest="0" * 64,
            expected_external_network=_EXPECTED_EXTERNAL_NETWORK,
        )
    with pytest.raises(SkillBoundWebAnalysisRuntimeError):
        bind_skill_bound_web_analysis_provider_runtime(
            LocalWebAnalysisProviderAssembly(
                provider_runtime=runtime.base_runtime,
                finalizer=cast(Any, object()),
            ),
            transport_pin=case.transport_pin,
            expected_transport_pin_digest=case.transport_pin.pin_digest,
            expected_external_network="foreign-network",
        )


@pytest.mark.asyncio
async def test_runtime_dispatches_exactly_once_without_tools_and_seals_success_run(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    runtime_verified_source: VerifiedAuthenticatedDiscoveryRun,
) -> None:
    case = _build_case(
        tmp_path,
        sample_campaign,
        runtime_verified_source,
        content=None,
    )
    case.gateway.content = _successor_content(case.skill_run)
    runtime = _runtime(case)

    completion = await _invoke(runtime, case)

    assert case.gateway.calls == 1
    assert len(case.gateway.requests) == 1
    chat = ProviderChatRequest.model_validate(case.gateway.requests[0].arguments)
    assert chat.tools == []
    assert chat.tool_choice == "none"
    assert chat.parallel_tool_calls is False
    assert chat.stream is False
    assert chat.response_format is not None
    assert chat.response_format.json_schema.name == SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME
    assert [message.role.value for message in chat.messages] == ["developer", "user"]

    assert isinstance(completion.receipt, SkillBoundWebAnalysisInvocationReceipt)
    assert completion.receipt.request_envelope.request_id == case.gateway.requests[0].request_id
    assert completion.receipt.successor_provider_execution_context == (
        case.provider_runtime.execution_context
    )
    assert completion.receipt.compiled_proposal == completion.proposal
    assert completion.receipt.dispatch_count == 1
    assert completion.receipt.target_request_count == 0
    assert completion.receipt.automatic_redispatch_authorized is False
    assert completion.receipt.execution_authorized is False

    snapshot = load_verified_run_snapshot(
        completion.publication.run_path,
        expected_run_id=completion.publication.run_id,
    )
    assert {artifact.path for artifact in snapshot.seals[0].artifacts} == {
        "skill-bound-snapshot.json",
        "skill-bound-request.json",
        "skill-bound-provider-execution-context.json",
        "provider-outcome.json",
        "skill-bound-draft.json",
        "compiled-skill-bound-proposal.json",
        "skill-bound-invocation-receipt.json",
    }
    assert tuple(event.event_type for event in snapshot.events) == (
        "web-analysis.skill-bound.invocation.started",
        "web-analysis.skill-bound.invocation.completed",
    )
    assert verify_run_integrity(completion.publication.run_path).seal_count == 1
    loaded = _success_load(case, completion)
    assert loaded.receipt == completion.receipt
    assert loaded.draft == completion.draft
    assert loaded.proposal == completion.proposal

    with pytest.raises(SkillBoundWebAnalysisRuntimeError, match="already consumed"):
        await _invoke(runtime, case)
    assert case.gateway.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "content",
        "failure",
        "terminal_state",
        "provider_outcome_expected",
        "raw_draft_expected",
    ),
    (
        (
            "not-json",
            None,
            "provider-response-rejected",
            True,
            True,
        ),
        (
            "x" * (256 * 1024 + 1),
            None,
            "provider-response-rejected",
            True,
            False,
        ),
        (
            None,
            TimeoutError("fixture timeout"),
            "provider-invocation-failed-uncertain",
            False,
            False,
        ),
    ),
)
async def test_terminal_failures_seal_once_and_never_redispatch(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    runtime_verified_source: VerifiedAuthenticatedDiscoveryRun,
    content: str | None,
    failure: BaseException | None,
    terminal_state: str,
    provider_outcome_expected: bool,
    raw_draft_expected: bool,
) -> None:
    case = _build_case(
        tmp_path,
        sample_campaign,
        runtime_verified_source,
        content=content,
        failure=failure,
    )
    runtime = _runtime(case)

    with pytest.raises(SkillBoundWebAnalysisRuntimeError) as caught:
        await _invoke(runtime, case)

    assert case.gateway.calls == 1
    terminal = _failure_load(case, caught.value)
    assert isinstance(terminal.receipt, SkillBoundWebAnalysisInvocationFailureReceipt)
    assert terminal.receipt.terminal_state == terminal_state
    assert terminal.receipt.dispatch_count == 1
    assert terminal.receipt.target_request_count == 0
    assert terminal.receipt.automatic_redispatch_authorized is False
    assert terminal.receipt.execution_authorized is False
    snapshot = load_verified_run_snapshot(
        caught.value.publication.run_path,
        expected_run_id=caught.value.publication.run_id,
    )
    artifacts = {artifact.path for artifact in snapshot.seals[0].artifacts}
    assert {
        "skill-bound-snapshot.json",
        "skill-bound-request.json",
        "skill-bound-provider-execution-context.json",
        "skill-bound-invocation-failure.json",
    } <= artifacts
    assert ("provider-outcome.json" in artifacts) is provider_outcome_expected
    assert ("skill-bound-rejected-draft.bin" in artifacts) is raw_draft_expected
    assert "compiled-skill-bound-proposal.json" not in artifacts
    assert "skill-bound-invocation-receipt.json" not in artifacts
    assert tuple(event.event_type for event in snapshot.events) == (
        "web-analysis.skill-bound.invocation.started",
        "web-analysis.skill-bound.invocation.failed",
    )
    assert verify_run_integrity(caught.value.publication.run_path).seal_count == 1

    with pytest.raises(SkillBoundWebAnalysisRuntimeError, match="already consumed"):
        await _invoke(runtime, case)
    assert case.gateway.calls == 1


@pytest.mark.asyncio
async def test_pre_start_failure_records_zero_dispatch_and_strictly_reloads(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    runtime_verified_source: VerifiedAuthenticatedDiscoveryRun,
) -> None:
    case = _build_case(
        tmp_path,
        sample_campaign,
        runtime_verified_source,
        content=None,
    )
    runtime = _runtime(case)
    base = case.provider_runtime.base_runtime
    base.ledger.consume(base.grant.grant_id)

    with pytest.raises(SkillBoundWebAnalysisRuntimeError) as caught:
        await _invoke(runtime, case)

    assert case.gateway.calls == 0
    terminal = _failure_load(case, caught.value)
    assert terminal.receipt.dispatch_count == 0
    assert terminal.dispatch_count == 0
    assert terminal.receipt.terminal_state == "provider-invocation-failed-uncertain"
    provider_publication = caught.value.provider_publication
    assert provider_publication is not None
    provider_snapshot = load_verified_run_snapshot(
        provider_publication.run_path,
        expected_run_id=provider_publication.run_id,
    )
    assert "model.call.started" not in {event.event_type for event in provider_snapshot.events}
    assert verify_run_integrity(provider_publication.run_path).seal_count == 1


@pytest.mark.asyncio
async def test_before_worker_dispatch_cancellation_binds_request_lease_and_cleanup(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    runtime_verified_source: VerifiedAuthenticatedDiscoveryRun,
) -> None:
    gateway = _BeforeDispatchCancellationGateway(content=None)
    case = _build_case(
        tmp_path,
        sample_campaign,
        runtime_verified_source,
        content=None,
        gateway=gateway,
    )

    with pytest.raises(SkillBoundWebAnalysisCancelledError) as caught:
        await _invoke(_runtime(case), case)

    terminal = _failure_load(case, caught.value)
    assert gateway.calls == 1
    assert terminal.dispatch_count == 1
    assert terminal.receipt.dispatch_count == 1
    assert terminal.receipt.terminal_state == "provider-invocation-failed-uncertain"
    provider_publication = caught.value.provider_publication
    snapshot = load_verified_run_snapshot(
        provider_publication.run_path,
        expected_run_id=provider_publication.run_id,
    )
    event_types = tuple(event.event_type for event in snapshot.events)
    assert "worker.dispatched" not in event_types
    assert "worker.cancelled" in event_types
    assert verify_run_integrity(provider_publication.run_path).seal_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "request-digest",
        "coherent-request-digest",
        "policy-tool",
        "lease-scope",
        "cancel-execution-id",
    ],
)
async def test_before_dispatch_cancellation_rejects_foreign_lineage(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    runtime_verified_source: VerifiedAuthenticatedDiscoveryRun,
    mutation: str,
) -> None:
    gateway = _BeforeDispatchCancellationGateway(content=None, mutation=mutation)
    case = _build_case(
        tmp_path,
        sample_campaign,
        runtime_verified_source,
        content=None,
        gateway=gateway,
    )

    with pytest.raises(WebAnalysisRunIntegrityError):
        await _invoke(_runtime(case), case)
    assert gateway.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    ["lease-uses", "worker-backend", "coherent-worker-backend", "network-trust"],
)
async def test_successor_evidence_rejects_worker_and_lease_provenance_drift(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    runtime_verified_source: VerifiedAuthenticatedDiscoveryRun,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    case = _build_case(
        tmp_path,
        sample_campaign,
        runtime_verified_source,
        content=None,
    )
    case.gateway.content = _successor_content(case.skill_run)
    provider_store = case.provider_runtime.base_runtime.store
    original = RunStore.write_json_create_only

    def mutate_evidence(store: RunStore, relative_path: str, payload: object) -> str:
        if store is provider_store and relative_path.startswith("evidence/"):
            wire = json.loads(json.dumps(payload))
            if mutation == "lease-uses":
                wire["secretLeases"][0]["max_uses"] = 2
            elif mutation in {"worker-backend", "coherent-worker-backend"}:
                wire["workerResult"]["backend"] = "simulated"
            else:
                wire["networkLogTrusted"] = False
            payload = wire
        return original(store, relative_path, payload)

    event_original = RunStore.append_event

    def mutate_event(
        store: RunStore,
        event_type: str,
        payload: dict[str, object],
    ) -> object:
        if (
            store is provider_store
            and event_type == "worker.completed"
            and mutation == "coherent-worker-backend"
        ):
            payload = {**payload, "backend": "simulated"}
        return event_original(store, event_type, payload)

    monkeypatch.setattr(RunStore, "write_json_create_only", mutate_evidence)
    monkeypatch.setattr(RunStore, "append_event", mutate_event)
    with pytest.raises(WebAnalysisRunIntegrityError):
        await _invoke(_runtime(case), case)
    assert case.gateway.calls == 1


@pytest.mark.asyncio
async def test_skill_bound_artifact_rejects_default_synthesized_transport_pin_wire(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    runtime_verified_source: VerifiedAuthenticatedDiscoveryRun,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _build_case(
        tmp_path,
        sample_campaign,
        runtime_verified_source,
        content=None,
    )
    case.gateway.content = _successor_content(case.skill_run)
    original = RunStore.write_json_create_only

    def omit_pin_digest(store: RunStore, relative_path: str, payload: object) -> str:
        if relative_path == "skill-bound-provider-execution-context.json":
            wire = json.loads(json.dumps(payload))
            del wire["transportPin"]["pinDigest"]
            payload = wire
        return original(store, relative_path, payload)

    monkeypatch.setattr(RunStore, "write_json_create_only", omit_pin_digest)
    with pytest.raises(SkillBoundWebAnalysisRuntimeError):
        await _invoke(_runtime(case), case)
    assert case.gateway.calls == 1


@pytest.mark.asyncio
async def test_successor_provider_verifier_cannot_omit_or_partially_supply_anchors(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    runtime_verified_source: VerifiedAuthenticatedDiscoveryRun,
) -> None:
    case = _build_case(
        tmp_path,
        sample_campaign,
        runtime_verified_source,
        content=None,
    )
    case.gateway.content = _successor_content(case.skill_run)
    completion = await _invoke(_runtime(case), case)
    successor_publication = completion.provider_publication
    base_context = case.provider_runtime.execution_context.base_provider_execution_context
    base_publication = WebAnalysisProviderRunPublication(
        run_path=successor_publication.run_path,
        run_id=successor_publication.run_id,
        root_digest=successor_publication.root_digest,
        execution_context=base_context,
    )

    with pytest.raises(WebAnalysisRunIntegrityError):
        verify_web_analysis_provider_run_publication(
            base_publication,
            expected_execution_context=base_context,
            expected_role="skill-bound-web-analysis-proposal",
            expected_attempt=1,
            expected_schema_name=SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
        )
    with pytest.raises(WebAnalysisRunIntegrityError):
        verify_web_analysis_provider_run_publication(
            base_publication,
            expected_execution_context=base_context,
            expected_role="skill-bound-web-analysis-proposal",
            expected_attempt=1,
            expected_schema_name=SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
            expected_registration=case.provider_runtime.base_runtime.registration,
        )

    unknown_wire = base_context.model_dump(mode="json", by_alias=True)
    unknown_wire["contextId"] = ""
    unknown_wire["contextDigest"] = ""
    unknown_nested = cast(
        dict[str, object],
        cast(dict[str, object], unknown_wire["toolStableExecutionContext"])["context"],
    )
    unknown_nested["implementationVersion"] = "pajin.tool-adapter/web-analysis-transport-v3"
    unknown_nested.pop("webAnalysisTransport")
    unknown_nested.pop("providerWorker")
    unknown_context = WebAnalysisProviderExecutionContext.model_validate(unknown_wire)
    with pytest.raises(WebAnalysisRunIntegrityError):
        verify_web_analysis_provider_run_publication(
            WebAnalysisProviderRunPublication(
                run_path=successor_publication.run_path,
                run_id=successor_publication.run_id,
                root_digest=successor_publication.root_digest,
                execution_context=unknown_context,
            ),
            expected_execution_context=unknown_context,
            expected_role="skill-bound-web-analysis-proposal",
            expected_attempt=1,
            expected_schema_name=SKILL_BOUND_WEB_ANALYSIS_RESPONSE_SCHEMA_NAME,
        )


@pytest.mark.asyncio
async def test_strict_loader_rejects_foreign_anchor_and_tampered_artifact(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    runtime_verified_source: VerifiedAuthenticatedDiscoveryRun,
) -> None:
    case = _build_case(
        tmp_path,
        sample_campaign,
        runtime_verified_source,
        content=None,
    )
    case.gateway.content = _successor_content(case.skill_run)
    completion = await _invoke(_runtime(case), case)

    assert _success_load(case, completion).receipt == completion.receipt
    provider_publication = completion.provider_publication
    with pytest.raises(SkillBoundWebAnalysisRuntimeError):
        load_verified_skill_bound_web_analysis_invocation(
            completion.publication.run_path,
            expected_run_id=completion.publication.run_id,
            expected_root_digest=completion.publication.root_digest,
            source=case.source,
            skill_run=case.skill_run,
            transport_pin=case.transport_pin,
            registration=case.provider_runtime.base_runtime.registration,
            provider_run_path=provider_publication.run_path,
            expected_provider_run_id=provider_publication.run_id,
            expected_provider_root_digest=provider_publication.root_digest,
            expected_provider_execution_context=case.provider_runtime.execution_context,
            expected_source_run_id=case.source.verification.run_id,
            expected_source_root_digest=case.source.verification.root_digest,
            expected_skill_run_id=case.skill_run.verification.run_id,
            expected_skill_root_digest=case.skill_run.verification.root_digest,
            expected_registry_ref=case.skill_run.index.registry,
            expected_policy_digest=case.skill_run.index.selection_policy_digest,
            expected_transport_pin_digest="0" * 64,
            expected_external_network=_EXPECTED_EXTERNAL_NETWORK,
        )

    with pytest.raises(SkillBoundWebAnalysisRuntimeError):
        load_verified_skill_bound_web_analysis_invocation(
            completion.publication.run_path,
            expected_run_id=completion.publication.run_id,
            expected_root_digest=completion.publication.root_digest,
            source=case.source,
            skill_run=case.skill_run,
            transport_pin=case.transport_pin,
            registration=case.provider_runtime.base_runtime.registration,
            provider_run_path=provider_publication.run_path,
            expected_provider_run_id=provider_publication.run_id,
            expected_provider_root_digest=provider_publication.root_digest,
            expected_provider_execution_context=case.provider_runtime.execution_context,
            expected_source_run_id=case.source.verification.run_id,
            expected_source_root_digest=case.source.verification.root_digest,
            expected_skill_run_id=case.skill_run.verification.run_id,
            expected_skill_root_digest=case.skill_run.verification.root_digest,
            expected_registry_ref=case.skill_run.index.registry,
            expected_policy_digest=case.skill_run.index.selection_policy_digest,
            expected_transport_pin_digest=case.transport_pin.pin_digest,
            expected_external_network="foreign-network",
        )

    (completion.publication.run_path / "skill-bound-invocation-receipt.json").write_text(
        json.dumps({"tampered": True}),
        encoding="utf-8",
    )
    with pytest.raises(SkillBoundWebAnalysisRuntimeError):
        _success_load(case, completion)
