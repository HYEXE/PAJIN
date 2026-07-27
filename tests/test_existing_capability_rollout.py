from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from pajin.capabilities import (
    CapabilityBenchmarkMapping,
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityMaturity,
    CapabilityMetricsReportStatus,
    CapabilityReleaseBundle,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    CapabilityUseProfile,
    ExistingModeCapabilityActivation,
    ExistingModeCapabilityActivationError,
    ExistingModeCapabilityActivationSet,
    ExistingModeCapabilityBundle,
    ExistingModeCapabilityGatewayDispatcher,
    ExistingModeCapabilityReleaseSet,
    ExistingModeCapabilityRollout,
    ExistingModeCapabilityRolloutError,
    PreparedCapabilityAction,
    activate_existing_mode_capabilities,
    admit_existing_mode_capability_releases,
    capability_gateway_outcome_digest,
    capability_lifecycle_public_key,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
    existing_mode_capability_benchmark_mappings,
    existing_mode_capability_bundle,
    existing_mode_capability_rollout_metrics,
    registered_action_capability,
)
from pajin.domain.ctf import CTFScenario
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    ToolRequest,
    ToolRiskTier,
)
from pajin.graph import ActionPermitError
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import RunStore, load_verified_run_events
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.gateway import ToolGateway
from pajin.tools.mock import MockAgentProbe

NOW = datetime(2026, 7, 27, 6, tzinfo=UTC)
REVIEWED_AT = NOW - timedelta(days=2)
RELEASED_AT = NOW - timedelta(days=1)


def _bundle() -> ExistingModeCapabilityBundle:
    tools = ToolRegistry()
    for tool in (
        MockAgentProbe(),
        AIChatProbeTool(),
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
    ):
        tools.register(tool)
    return existing_mode_capability_bundle(tools)


def _seed(label: str) -> bytes:
    return sha256(label.encode("utf-8")).digest()


def _signer(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
    key_id: str | None = None,
) -> tuple[CapabilityLifecycleTrustKey, CapabilityLifecycleSigner]:
    key = CapabilityLifecycleTrustKey(
        keyId=key_id or f"test.rollout.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=30),
    )
    return (
        key,
        CapabilityLifecycleSigner.from_private_key_bytes(
            key=key,
            private_key=_seed(label),
        ),
    )


def _signing_authority() -> tuple[
    tuple[CapabilityLifecycleTrustKey, ...],
    CapabilityLifecycleSigner,
    CapabilityLifecycleSigner,
]:
    publisher_key, publisher = _signer(
        "publisher",
        principal="test.rollout.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key, reviewer = _signer(
        "reviewer",
        principal="test.rollout.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    return (publisher_key, reviewer_key), publisher, reviewer


def _signed_releases(
    bundle: ExistingModeCapabilityBundle,
    *,
    policy: CapabilityLifecyclePolicy,
    publisher: CapabilityLifecycleSigner,
    reviewer: CapabilityLifecycleSigner,
) -> tuple[CapabilityReleaseBundle, ...]:
    releases: list[CapabilityReleaseBundle] = []
    for capability in bundle.capabilities():
        reference = capability.reference()
        review = CapabilityReviewStatement(
            capability=reference,
            targetMaturity=CapabilityMaturity.EXPERIMENTAL,
            sequence=1,
            previousReleaseDigest=None,
            policyDigest=policy.digest,
            reviewerPrincipalId=reviewer.key.principal_id,
            checklistDigest=sha256(
                f"CAP-005 rollout:{reference.capability.capability_id}".encode()
            ).hexdigest(),
            decision=CapabilityReviewDecision.APPROVED,
            issuedAt=REVIEWED_AT,
            expiresAt=NOW + timedelta(days=1),
        )
        signed_review = reviewer.sign_review(review)
        release = CapabilityReleaseStatement(
            capability=reference,
            maturity=CapabilityMaturity.EXPERIMENTAL,
            sequence=1,
            previousReleaseDigest=None,
            policyDigest=policy.digest,
            reviewDigests=(review.review_digest,),
            publisherPrincipalId=publisher.key.principal_id,
            issuedAt=RELEASED_AT,
        )
        releases.append(
            CapabilityReleaseBundle(
                release=publisher.sign_release(release),
                reviews=(signed_review,),
            )
        )
    return tuple(releases)


def _rollout_inputs() -> tuple[
    ExistingModeCapabilityBundle,
    CapabilityLifecyclePolicy,
    tuple[CapabilityLifecycleTrustKey, ...],
    tuple[CapabilityReleaseBundle, ...],
]:
    bundle = _bundle()
    policy = CapabilityLifecyclePolicy.reference_policy()
    keys, publisher, reviewer = _signing_authority()
    releases = _signed_releases(
        bundle,
        policy=policy,
        publisher=publisher,
        reviewer=reviewer,
    )
    return bundle, policy, keys, releases


def _admit(
    *,
    releases: tuple[CapabilityReleaseBundle, ...] | None = None,
    trust_keys: tuple[CapabilityLifecycleTrustKey, ...] | None = None,
):
    bundle, policy, default_keys, default_releases = _rollout_inputs()
    return admit_existing_mode_capability_releases(
        bundle=bundle,
        policy=policy,
        trust_keys=default_keys if trust_keys is None else trust_keys,
        releases=default_releases if releases is None else releases,
        clock=lambda: NOW,
    )


def _release_for(
    rollout: ExistingModeCapabilityRollout,
    capability_id: str,
):
    return next(
        item.release
        for item in rollout.release_set.bindings
        if item.capability.capability.capability_id == capability_id
    )


def _web_ai_activation(
    rollout: ExistingModeCapabilityRollout,
) -> ExistingModeCapabilityActivation:
    return activate_existing_mode_capabilities(
        rollout=rollout,
        releases=(
            _release_for(rollout, "pajin.ctf.web-exposed-backup-config"),
            _release_for(rollout, "pajin.ai.kisa.system-prompt-disclosure"),
        ),
        profile=CapabilityUseProfile.RANGE,
    )


def _web_action(
    activation: ExistingModeCapabilityActivation,
) -> PreparedCapabilityAction:
    return activation.prepare_action(
        release=_release_for(
            activation.rollout,
            "pajin.ctf.web-exposed-backup-config",
        ),
        request=ToolRequest(
            request_id="tool_capability_activation_web",
            agent_id="agent:planner-local",
            tool_id="ctf.web-backup-probe",
            target="http://host.docker.internal:8780/.env.backup",
            method="GET",
        ),
        parameters={
            "challengeId": "activation-web",
            "scenarioId": CTFScenario.WEB_EXPOSED_BACKUP_CONFIG.value,
        },
    )


def _mock_action(
    rollout: ExistingModeCapabilityRollout,
) -> tuple[ExistingModeCapabilityActivation, PreparedCapabilityAction]:
    release = _release_for(
        rollout,
        "pajin.ai.kisa.indirect-tool-hijacking",
    )
    activation = activate_existing_mode_capabilities(
        rollout=rollout,
        releases=(release,),
        profile=CapabilityUseProfile.RANGE,
    )
    prepared = activation.prepare_action(
        release=release,
        request=ToolRequest(
            request_id="tool_capability_gateway_dispatch",
            agent_id="agent:planner-local",
            tool_id="mock.agent-probe",
            target="https://staging.example.invalid/api/chat",
            method="POST",
        ),
        parameters={"simulation": {"unauthorizedToolCall": True}},
    )
    return activation, prepared


class _PermitDispatcherStub:
    def __init__(self, permit: SimpleNamespace) -> None:
        self.permit = permit
        self.calls = 0

    async def dispatch_once(
        self,
        _envelope: object,
        _proposal: object,
        _decision: object,
        dispatch,
    ):
        self.calls += 1
        result = await dispatch(self.permit)
        return SimpleNamespace(
            permit=self.permit,
            dispatched=True,
            result=result,
        )


class _RaisingGateway:
    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.calls = 0

    async def execute(self, *_args, **_kwargs):
        self.calls += 1
        raise self.error


class _FailingAuditStore:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.calls = 0

    def append_event(self, *_args, **_kwargs):
        self.calls += 1
        raise RuntimeError("audit storage unavailable")


def _dispatch_authority(
    *,
    campaign_id: str,
    run_id: str,
    prepared: PreparedCapabilityAction,
    expires_at: datetime = NOW + timedelta(days=1),
) -> tuple[SimpleNamespace, SimpleNamespace]:
    proposal = SimpleNamespace(
        campaign_id=campaign_id,
        run_id=run_id,
        proposal_id="action-proposal_" + "a" * 64,
        proposal_digest="b" * 64,
        capability=prepared.capability,
        request_id=prepared.request.request_id,
        request_digest=prepared.request_digest,
        normalized_parameters_digest=prepared.normalized_parameters_digest,
        reservation=SimpleNamespace(request_units=1),
    )
    permit = SimpleNamespace(
        permit_id="action-permit_" + "c" * 64,
        permit_digest="d" * 64,
        dispatch_id="action-dispatch_" + "e" * 64,
        campaign_id=campaign_id,
        run_id=run_id,
        proposal_id=proposal.proposal_id,
        proposal_digest=proposal.proposal_digest,
        capability=prepared.capability,
        request_id=prepared.request.request_id,
        request_digest=prepared.request_digest,
        normalized_parameters_digest=prepared.normalized_parameters_digest,
        expires_at=expires_at,
    )
    return proposal, permit


def _dispatch_grant(
    prepared: PreparedCapabilityAction,
    campaign: CampaignManifest,
) -> CapabilityGrant:
    return CapabilityGrant(
        subject=prepared.request.agent_id,
        campaign=campaign.metadata.name,
        tools={prepared.request.tool_id},
        targets={prepared.request.target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        issued_at=campaign.spec.authorization.approved_at,
        expires_at=campaign.spec.authorization.expires_at,
    )


def test_existing_mode_benchmark_mappings_cover_exact_seven_capabilities() -> None:
    bundle = _bundle()

    mappings = existing_mode_capability_benchmark_mappings(bundle)

    assert len(mappings) == 7
    assert {item.capability for item in mappings} == {
        item.capability for item in bundle.capabilities()
    }
    assert len({item.mapping_digest for item in mappings}) == 7
    assert all(item.benchmark_ids[0].startswith("pajin.benchmark.") for item in mappings)
    assert mappings == existing_mode_capability_benchmark_mappings(bundle)


def test_rollout_verifies_all_external_signatures_and_is_order_independent() -> None:
    bundle, policy, keys, releases = _rollout_inputs()

    forward = admit_existing_mode_capability_releases(
        bundle=bundle,
        policy=policy,
        trust_keys=keys,
        releases=releases,
        clock=lambda: NOW,
    )
    reverse = admit_existing_mode_capability_releases(
        bundle=bundle,
        policy=policy,
        trust_keys=tuple(reversed(keys)),
        releases=tuple(reversed(releases)),
        clock=lambda: NOW,
    )

    assert forward.release_set.release_set_digest == (reverse.release_set.release_set_digest)
    assert len(forward.release_set.bindings) == 7
    assert forward.release_set.policy_digest == policy.digest
    for binding in forward.release_set.bindings:
        resolved = forward.lifecycle.resolve_for_use(
            binding.release,
            CapabilityUseProfile.RANGE,
        )
        assert resolved.capability.reference() == binding.capability
        assert resolved.maturity is CapabilityMaturity.EXPERIMENTAL


def test_rollout_metrics_promote_only_verified_mapping_and_lifecycle_coverage() -> None:
    rollout = _admit()

    report = existing_mode_capability_rollout_metrics(
        rollout,
        measured_at=NOW,
    )

    assert report.status is CapabilityMetricsReportStatus.INCOMPLETE
    assert report.registry.definition_coverage.value == 1
    assert report.registry.authority_coverage.value == 1
    assert report.registry.benchmark_mapping_coverage.value == 1
    assert report.lead_time.delivery_coverage.value == 0
    assert report.oracle.authority_coverage.value == 1
    assert report.oracle.observation_coverage.value == 0
    assert report.replay.support_coverage.value == 1
    assert report.replay.observation_coverage.value == 0
    assert report.lifecycle.release_coverage.value == 1
    assert report.lifecycle.experimental_count == 7
    assert len(report.inputs.benchmark_mapping_digests) == 7
    assert len(report.inputs.lifecycle_release_digests) == 7
    assert len(report.gaps) == 17


def test_rollout_rejects_missing_and_duplicate_release_inventory() -> None:
    bundle, policy, keys, releases = _rollout_inputs()

    with pytest.raises(ExistingModeCapabilityRolloutError, match="exactly seven"):
        admit_existing_mode_capability_releases(
            bundle=bundle,
            policy=policy,
            trust_keys=keys,
            releases=releases[:-1],
            clock=lambda: NOW,
        )
    duplicated = (*releases[:-1], releases[0])
    with pytest.raises(
        ExistingModeCapabilityRolloutError,
        match="failed lifecycle verification",
    ):
        admit_existing_mode_capability_releases(
            bundle=bundle,
            policy=policy,
            trust_keys=keys,
            releases=duplicated,
            clock=lambda: NOW,
        )


def test_rollout_rejects_signature_authority_substitution() -> None:
    bundle, policy, keys, releases = _rollout_inputs()
    substituted_key, _substituted_signer = _signer(
        "substituted-reviewer",
        principal=keys[1].principal_id,
        role=CapabilityLifecycleKeyRole.REVIEWER,
        key_id=keys[1].key_id,
    )

    with pytest.raises(
        ExistingModeCapabilityRolloutError,
        match="failed lifecycle verification",
    ):
        admit_existing_mode_capability_releases(
            bundle=bundle,
            policy=policy,
            trust_keys=(keys[0], substituted_key),
            releases=releases,
            clock=lambda: NOW,
        )


def test_release_set_and_rollout_reject_identity_and_mapping_drift() -> None:
    rollout = _admit()
    payload = rollout.release_set.model_dump(mode="json", by_alias=True)
    payload["releaseSetDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="release-set digest"):
        ExistingModeCapabilityReleaseSet.model_validate(payload)

    first = rollout.benchmark_mappings[0]
    drifted = CapabilityBenchmarkMapping(
        capability=first.capability,
        benchmarkIds=first.benchmark_ids,
        expectedObservables=("A different observable was substituted.",),
    )
    mappings = tuple(
        sorted(
            (drifted, *rollout.benchmark_mappings[1:]),
            key=lambda item: (
                item.capability.capability_id,
                item.capability.capability_version,
                item.capability.capability_digest,
            ),
        )
    )
    with pytest.raises(
        ExistingModeCapabilityRolloutError,
        match="differ from code authority",
    ):
        ExistingModeCapabilityRollout(
            bundle=rollout.bundle,
            lifecycle=rollout.lifecycle,
            release_set=rollout.release_set,
            benchmark_mappings=mappings,
        )


def test_signed_rollout_activates_explicit_web_and_ai_graph_subset() -> None:
    rollout = _admit()

    activation = _web_ai_activation(rollout)
    reversed_activation = activate_existing_mode_capabilities(
        rollout=rollout,
        releases=tuple(
            reversed(
                (
                    _release_for(
                        rollout,
                        "pajin.ctf.web-exposed-backup-config",
                    ),
                    _release_for(
                        rollout,
                        "pajin.ai.kisa.system-prompt-disclosure",
                    ),
                )
            )
        ),
        profile=CapabilityUseProfile.RANGE,
    )

    assert activation.activation_set.activation_set_digest == (
        reversed_activation.activation_set.activation_set_digest
    )
    assert activation.activation_set.release_set_digest == (rollout.release_set.release_set_digest)
    assert {item.domain for item in activation.activation_set.bindings} == {
        "ai-redteam",
        "ctf",
    }
    assert {
        surface
        for item in activation.activation_set.bindings
        for surface in item.supported_surface_types
    } >= {"ctf-web"}
    registry = activation.action_registry()
    for binding in activation.activation_set.bindings:
        assert registry.resolve(binding.action_capability.reference()) == (
            binding.action_capability
        )

    inactive = next(
        item
        for item in rollout.bundle.definitions.definitions()
        if item.capability_id == "pajin.ctf.crypto-single-byte-xor"
    )
    with pytest.raises(ActionPermitError, match="not registered"):
        registry.resolve(registered_action_capability(inactive).reference())


def test_activation_rejects_disallowed_profile_duplicate_and_rollout_drift() -> None:
    rollout = _admit()
    web = _release_for(rollout, "pajin.ctf.web-exposed-backup-config")

    with pytest.raises(
        ExistingModeCapabilityActivationError,
        match="not an executable member",
    ):
        activate_existing_mode_capabilities(
            rollout=rollout,
            releases=(web,),
            profile=CapabilityUseProfile.PENTEST,
        )
    with pytest.raises(
        ExistingModeCapabilityActivationError,
        match="duplicate",
    ):
        activate_existing_mode_capabilities(
            rollout=rollout,
            releases=(web, web),
            profile=CapabilityUseProfile.RANGE,
        )

    activation = _web_ai_activation(rollout)
    drifted_set = ExistingModeCapabilityActivationSet(
        releaseSetDigest="0" * 64,
        profile=activation.activation_set.profile,
        bindings=activation.activation_set.bindings,
    )
    with pytest.raises(
        ExistingModeCapabilityActivationError,
        match="another signed release set",
    ):
        ExistingModeCapabilityActivation(
            rollout=rollout,
            activation_set=drifted_set,
        )


def test_activation_prepares_exact_cap002_request_and_graph_digests() -> None:
    activation = _web_ai_activation(_admit())

    prepared = _web_action(activation)

    assert prepared.request.arguments == {
        "challengeId": "activation-web",
        "scenarioId": CTFScenario.WEB_EXPOSED_BACKUP_CONFIG.value,
    }
    assert prepared.request_digest == capability_tool_request_digest(prepared.request)
    assert prepared.normalized_parameters_digest == (
        capability_normalized_parameters_digest(prepared.request.arguments)
    )
    assert activation.resolve_for_dispatch(prepared.capability).release == (prepared.release)

    raw = prepared.model_dump(mode="json", by_alias=True)
    raw["requestDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="request digest differs"):
        PreparedCapabilityAction.model_validate(raw)


@pytest.mark.asyncio
async def test_gateway_dispatch_requires_exact_prepared_graph_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    activation, prepared = _mock_action(_admit())
    tools = ToolRegistry()
    tools.register(MockAgentProbe())
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    proposal, permit = _dispatch_authority(
        campaign_id=sample_campaign.metadata.name,
        run_id=store.run_id,
        prepared=prepared,
    )
    permits = _PermitDispatcherStub(permit)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=tools,
        worker=SimulatedWorkerBackend(),
        store=store,
    )
    dispatcher = ExistingModeCapabilityGatewayDispatcher(
        activation=activation,
        permits=permits,
        gateway=gateway,
        audit_store=store,
        clock=lambda: NOW,
    )
    grant = _dispatch_grant(prepared, sample_campaign)

    result = await dispatcher.dispatch_once(
        SimpleNamespace(),
        proposal,
        SimpleNamespace(),
        prepared,
        campaign=sample_campaign,
        grant=grant,
        used_calls=0,
    )

    assert result.dispatched is True
    assert result.result is not None
    assert result.result.executed is True
    assert result.result.result.success is True
    assert permits.calls == 1
    reservation = json.loads(
        (store.path / "requests" / f"{prepared.request.request_id}.json").read_text(
            encoding="utf-8"
        )
    )
    assert reservation["requestSha256"] == prepared.request_digest
    store.seal()
    dispatch_events = [
        event
        for event in load_verified_run_events(store.path)
        if event.event_type.startswith("capability.dispatch.")
    ]
    assert [event.event_type for event in dispatch_events] == [
        "capability.dispatch.claimed",
        "capability.dispatch.completed",
    ]
    claimed, completed = (
        CapabilityDispatchAuditEvent.model_validate(event.payload) for event in dispatch_events
    )
    assert claimed.stage is CapabilityDispatchStage.CLAIMED
    assert completed.stage is CapabilityDispatchStage.COMPLETED
    assert completed.permit_id == permit.permit_id
    assert completed.permit_digest == permit.permit_digest
    assert completed.dispatch_id == permit.dispatch_id
    assert completed.activation_set_digest == prepared.activation_set_digest
    assert completed.gateway_outcome_digest == capability_gateway_outcome_digest(result.result)
    assert completed.executed is True
    assert completed.policy_allowed is True
    assert completed.tool_success is True

    tampered = dispatch_events[-1].payload | {"permitDigest": "0" * 64}
    with pytest.raises(ValidationError, match="event digest differs"):
        CapabilityDispatchAuditEvent.model_validate(tampered)

    mismatched = SimpleNamespace(**vars(proposal))
    mismatched.request_digest = "0" * 64
    with pytest.raises(
        ExistingModeCapabilityActivationError,
        match="differs from the prepared",
    ):
        await dispatcher.dispatch_once(
            SimpleNamespace(),
            mismatched,
            SimpleNamespace(),
            prepared,
            campaign=sample_campaign,
            grant=grant,
            used_calls=0,
        )
    assert permits.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected_stage"),
    [
        (RuntimeError("gateway failed"), CapabilityDispatchStage.FAILED),
        (asyncio.CancelledError(), CapabilityDispatchStage.CANCELLED),
    ],
)
async def test_gateway_dispatch_audits_failure_and_cancellation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    error: BaseException,
    expected_stage: CapabilityDispatchStage,
) -> None:
    activation, prepared = _mock_action(_admit())
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    proposal, permit = _dispatch_authority(
        campaign_id=sample_campaign.metadata.name,
        run_id=store.run_id,
        prepared=prepared,
    )
    gateway = _RaisingGateway(error)
    dispatcher = ExistingModeCapabilityGatewayDispatcher(
        activation=activation,
        permits=_PermitDispatcherStub(permit),
        gateway=gateway,
        audit_store=store,
        clock=lambda: NOW,
    )

    with pytest.raises(type(error)):
        await dispatcher.dispatch_once(
            SimpleNamespace(),
            proposal,
            SimpleNamespace(),
            prepared,
            campaign=sample_campaign,
            grant=_dispatch_grant(prepared, sample_campaign),
            used_calls=0,
        )

    store.seal()
    dispatch_events = [
        CapabilityDispatchAuditEvent.model_validate(event.payload)
        for event in load_verified_run_events(store.path)
        if event.event_type.startswith("capability.dispatch.")
    ]
    assert [event.stage for event in dispatch_events] == [
        CapabilityDispatchStage.CLAIMED,
        expected_stage,
    ]
    assert dispatch_events[-1].error_type is not None
    assert dispatch_events[-1].gateway_outcome_digest is None
    assert gateway.calls == 1


@pytest.mark.asyncio
async def test_gateway_dispatch_audits_expiry_without_calling_gateway(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    activation, prepared = _mock_action(_admit())
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    proposal, permit = _dispatch_authority(
        campaign_id=sample_campaign.metadata.name,
        run_id=store.run_id,
        prepared=prepared,
        expires_at=NOW,
    )
    gateway = _RaisingGateway(AssertionError("expired Permit reached Gateway"))
    dispatcher = ExistingModeCapabilityGatewayDispatcher(
        activation=activation,
        permits=_PermitDispatcherStub(permit),
        gateway=gateway,
        audit_store=store,
        clock=lambda: NOW,
    )

    with pytest.raises(
        ExistingModeCapabilityActivationError,
        match="expired before Tool Gateway",
    ):
        await dispatcher.dispatch_once(
            SimpleNamespace(),
            proposal,
            SimpleNamespace(),
            prepared,
            campaign=sample_campaign,
            grant=_dispatch_grant(prepared, sample_campaign),
            used_calls=0,
        )

    store.seal()
    dispatch_events = [
        CapabilityDispatchAuditEvent.model_validate(event.payload)
        for event in load_verified_run_events(store.path)
        if event.event_type.startswith("capability.dispatch.")
    ]
    assert [event.stage for event in dispatch_events] == [
        CapabilityDispatchStage.CLAIMED,
        CapabilityDispatchStage.EXPIRED,
    ]
    assert gateway.calls == 0


@pytest.mark.asyncio
async def test_gateway_dispatch_fails_closed_before_execution_when_audit_append_fails(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    activation, prepared = _mock_action(_admit())
    store = RunStore.create(tmp_path, sample_campaign.metadata.name)
    proposal, permit = _dispatch_authority(
        campaign_id=sample_campaign.metadata.name,
        run_id=store.run_id,
        prepared=prepared,
    )
    gateway = _RaisingGateway(AssertionError("unaudited dispatch reached Gateway"))
    audit_store = _FailingAuditStore(store.run_id)
    dispatcher = ExistingModeCapabilityGatewayDispatcher(
        activation=activation,
        permits=_PermitDispatcherStub(permit),
        gateway=gateway,
        audit_store=audit_store,
        clock=lambda: NOW,
    )

    with pytest.raises(RuntimeError, match="audit storage unavailable"):
        await dispatcher.dispatch_once(
            SimpleNamespace(),
            proposal,
            SimpleNamespace(),
            prepared,
            campaign=sample_campaign,
            grant=_dispatch_grant(prepared, sample_campaign),
            used_calls=0,
        )

    assert audit_store.calls == 1
    assert gateway.calls == 0
