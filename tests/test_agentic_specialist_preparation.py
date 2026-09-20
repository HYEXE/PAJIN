from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from pydantic import ValidationError

import pajin.agentic.specialist_preparation as specialist_preparation
from pajin.agentic.durable import (
    AgenticCoordinationBinding,
    AgenticCoordinationError,
    AgenticCoordinationStore,
    AgenticSpecialistExecutionEntry,
    AgenticSpecialistExecutionState,
    VerifiedSpecialistExecutionReservation,
)
from pajin.agentic.frontier import default_path_scoring_policy
from pajin.agentic.models import PentestSpecialization
from pajin.agentic.specialist_preparation import (
    AgenticSpecialistPreparation,
    AgenticSpecialistPreparationError,
    prepare_agentic_specialist_action,
)
from pajin.agentic.supervisor import DynamicSupervisorPolicy
from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import CampaignManifest, campaign_manifest_digest
from pajin.web_assessment.analysis_skill_projection import (
    registered_web_pentest_exploit_group,
)
from pajin.web_assessment.governed import _campaign
from pajin.web_assessment.governed_adapter_profile import (
    GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
    GOVERNED_JUICE_SHOP_ORIGIN,
    GOVERNED_WEB_CAMPAIGN_ID,
    GOVERNED_WEB_TARGET_ID,
    production_governed_web_adapter_profile_registry,
)

NOW = datetime(2026, 9, 18, 2, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64
STORE_ID = "agentic-store:" + "1" * 32


@dataclass(frozen=True, slots=True)
class PreparationFixture:
    store: AgenticCoordinationStore
    reservation: VerifiedSpecialistExecutionReservation
    entry: AgenticSpecialistExecutionEntry
    campaign: CampaignManifest
    graph_resolver: object
    graph_head: object
    seam_calls: list[object]


def _governed_campaign() -> CampaignManifest:
    registry = production_governed_web_adapter_profile_registry()
    profile = registry.resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )
    return _campaign(profile, now=NOW)


def _binding(
    campaign: CampaignManifest,
    *,
    allowed_target_ids: tuple[str, ...] = (GOVERNED_WEB_TARGET_ID,),
) -> AgenticCoordinationBinding:
    exploit_group = registered_web_pentest_exploit_group()
    supervisor_policy = DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0)
    scoring_policy = default_path_scoring_policy()
    return AgenticCoordinationBinding(
        controlPlaneRunId="agentic-control-plane:specialist-preparation",
        campaignId=campaign.metadata.name,
        campaignManifestDigest=campaign_manifest_digest(campaign),
        deploymentDigest=SHA_A,
        supervisorAgentId="agent:dynamic-supervisor",
        sourceSnapshotId="graph-snapshot:preparation",
        sourceSnapshotDigest=SHA_B,
        initialCheckpointId="agentic-checkpoint_" + SHA_C,
        initialCheckpointDigest=SHA_C,
        exploitGroupId=exploit_group.group_id,
        exploitGroupDigest=exploit_group.group_digest,
        exploitGroup=exploit_group,
        supervisorPolicyId=supervisor_policy.policy_id,
        supervisorPolicyDigest=supervisor_policy.policy_digest,
        supervisorPolicy=supervisor_policy,
        scoringPolicyId=scoring_policy.policy_id,
        scoringPolicyDigest=scoring_policy.policy_digest,
        scoringPolicy=scoring_policy,
        allowedTargetIds=allowed_target_ids,
    )


def _entry(
    binding: AgenticCoordinationBinding,
    *,
    target_id: str = GOVERNED_WEB_TARGET_ID,
    specialization: PentestSpecialization = PentestSpecialization.XSS,
    threat_class: str = "xss",
) -> AgenticSpecialistExecutionEntry:
    specialist = binding.exploit_group.specialist_for(specialization, threat_class)
    specialist_digest = (
        discovery_digest(
            "pajin.agentic.specialist-definition/v1",
            specialist.model_dump(mode="json", by_alias=True),
        )
        if specialist is not None
        else SHA_F
    )
    return AgenticSpecialistExecutionEntry(
        storeId=STORE_ID,
        coordinationBindingDigest=binding.binding_digest,
        sourceHeadCheckpointId="agentic-checkpoint_" + SHA_C,
        sourceHeadCheckpointDigest=SHA_C,
        graphSnapshotId="graph-snapshot:preparation",
        graphSnapshotDigest=SHA_B,
        cycleId="agentic-cycle_" + SHA_D,
        cycleDigest=SHA_D,
        commandId="agent-command_" + SHA_E,
        commandDigest=SHA_E,
        admissionReceiptId="agentic-command-admission_" + SHA_F,
        admissionReceiptDigest=SHA_F,
        targetAgentId="agent:specialist-xss-1",
        taskId="task:specialist-xss-1",
        candidateId="frontier-candidate_" + SHA_A,
        candidateDigest=SHA_A,
        proposalDigest=SHA_B,
        targetId=target_id,
        threatClass=threat_class,
        specialization=specialization,
        specialistDefinitionDigest=specialist_digest,
        state=AgenticSpecialistExecutionState.RESERVED,
        reservedAt=cast(Any, NOW.isoformat().replace("+00:00", "Z")),
    )


def _fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    campaign: CampaignManifest | None = None,
    target_id: str = GOVERNED_WEB_TARGET_ID,
    specialization: PentestSpecialization = PentestSpecialization.XSS,
    threat_class: str = "xss",
    allowed_target_ids: tuple[str, ...] = (GOVERNED_WEB_TARGET_ID,),
    seam_error: AgenticCoordinationError | None = None,
) -> PreparationFixture:
    selected_campaign = campaign or _governed_campaign()
    binding = _binding(selected_campaign, allowed_target_ids=allowed_target_ids)
    entry = _entry(
        binding,
        target_id=target_id,
        specialization=specialization,
        threat_class=threat_class,
    )
    store = object.__new__(AgenticCoordinationStore)
    store.binding = binding
    store.store_id = STORE_ID
    authority = object()
    reservation = VerifiedSpecialistExecutionReservation(entry, _authority=authority)
    seam_calls: list[object] = []

    def specialist_preparation_entry(
        observed_store: AgenticCoordinationStore,
        observed_reservation: VerifiedSpecialistExecutionReservation,
        *,
        graph_resolver: object,
        graph_head: object,
    ) -> AgenticSpecialistExecutionEntry:
        assert observed_store is store
        seam_calls.append((observed_reservation, graph_resolver, graph_head))
        if seam_error is not None:
            raise seam_error
        return entry

    monkeypatch.setattr(
        AgenticCoordinationStore,
        "specialist_preparation_entry",
        specialist_preparation_entry,
    )
    return PreparationFixture(
        store=store,
        reservation=reservation,
        entry=entry,
        campaign=selected_campaign,
        graph_resolver=object(),
        graph_head=object(),
        seam_calls=seam_calls,
    )


def _prepare(
    fixture: PreparationFixture,
    *,
    campaign: CampaignManifest | None = None,
) -> AgenticSpecialistPreparation:
    return prepare_agentic_specialist_action(
        store=fixture.store,
        reservation=fixture.reservation,
        graph_resolver=cast(Any, fixture.graph_resolver),
        graph_head=cast(Any, fixture.graph_head),
        campaign=campaign or fixture.campaign,
    )


def _authority_values(value: object) -> list[object]:
    observed: list[object] = []

    def visit(item: object) -> None:
        if type(item) is dict:
            for key, nested in cast(dict[str, object], item).items():
                if key.endswith("Authority"):
                    observed.append(nested)
                visit(nested)
        elif type(item) is list:
            for nested in cast(list[object], item):
                visit(nested)

    visit(value)
    return observed


def test_preparation_binds_exact_route_assignment_campaign_and_future_requirement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)

    first = _prepare(fixture)
    second = _prepare(fixture)

    assert first == second
    assert first.preparation_id == "agentic-specialist-preparation_" + first.preparation_digest
    assert first.store_id == STORE_ID
    assert first.coordination_binding_digest == fixture.store.binding.binding_digest
    assert first.reservation_id == fixture.entry.reservation_id
    assert first.source_head_checkpoint_digest == fixture.entry.source_head_checkpoint_digest
    assert first.graph_snapshot_digest == fixture.entry.graph_snapshot_digest
    assert first.command_digest == fixture.entry.command_digest
    assert first.candidate_digest == fixture.entry.candidate_digest
    assert first.specialization is PentestSpecialization.XSS
    assert first.threat_class == "xss"
    assert first.target_id == GOVERNED_WEB_TARGET_ID
    assert first.target_endpoint == GOVERNED_JUICE_SHOP_ORIGIN
    assert first.campaign_id == GOVERNED_WEB_CAMPAIGN_ID
    assert first.campaign_manifest_digest == campaign_manifest_digest(fixture.campaign)
    assert first.profile.profile_id.endswith("dom-xss-only")
    assert first.executor_id == "pajin.web-specialist.dom-xss"
    assert first.capability_requirement.max_calls == 1
    assert first.capability_requirement.delegable is False
    assert first.capability_requirement.fresh_approval_required is True
    assert first.capability_requirement.capability_registered is False
    assert first.capability_requirement.capability_granted is False
    wire = first.model_dump(mode="json", by_alias=True)
    assert _authority_values(wire)
    assert set(_authority_values(wire)) == {False}
    assert all(
        wire[key] is False
        for key in (
            "approvalSatisfied",
            "permitIssued",
            "gatewayDispatched",
            "workerDispatched",
            "executionStarted",
            "evidenceProduced",
            "findingProduced",
            "graphAdmitted",
        )
    )
    serialized = str(wire)
    assert "toolRequest" not in serialized
    assert "preparedAction" not in serialized
    assert "payload" not in serialized
    assert "transport" not in serialized
    assert len(fixture.seam_calls) == 2


def test_preparation_authority_markers_require_literal_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    prepared = _prepare(fixture)
    wire = prepared.model_dump(mode="json", by_alias=True)
    wire["approvalAuthority"] = True
    with pytest.raises(ValidationError, match="literal false"):
        AgenticSpecialistPreparation.model_validate(wire)

    wire = prepared.model_dump(mode="json", by_alias=True)
    cast(dict[str, object], wire["capabilityRequirement"])["workerAuthority"] = 0
    with pytest.raises(ValidationError, match="literal false"):
        AgenticSpecialistPreparation.model_validate(wire)


@pytest.mark.parametrize(
    ("specialization", "threat_class", "profile_suffix", "executor_id"),
    (
        (
            PentestSpecialization.XSS,
            "xss",
            "dom-xss-only",
            "pajin.web-specialist.dom-xss",
        ),
        (
            PentestSpecialization.SQL_INJECTION,
            "sql-injection",
            "sql-login-only",
            "pajin.web-specialist.sql-login",
        ),
        (
            PentestSpecialization.AUTHORIZATION,
            "authorization",
            "object-access-via-sql-login",
            "pajin.web-specialist.authorization",
        ),
    ),
)
def test_each_supported_assignment_resolves_one_exact_profile_and_executor(
    monkeypatch: pytest.MonkeyPatch,
    specialization: PentestSpecialization,
    threat_class: str,
    profile_suffix: str,
    executor_id: str,
) -> None:
    fixture = _fixture(
        monkeypatch,
        specialization=specialization,
        threat_class=threat_class,
    )

    prepared = _prepare(fixture)

    assert prepared.specialization is specialization
    assert prepared.threat_class == threat_class
    assert prepared.profile.profile_id.endswith(profile_suffix)
    assert prepared.executor_id == executor_id
    assert prepared.capability_requirement.profile == prepared.profile
    assert prepared.capability_requirement.executor_id == executor_id


def test_raw_audit_entry_and_caller_execution_inputs_fail_before_store_seam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)

    with pytest.raises(AgenticSpecialistPreparationError, match="verified reservation"):
        prepare_agentic_specialist_action(
            store=fixture.store,
            reservation=cast(Any, fixture.entry),
            graph_resolver=cast(Any, fixture.graph_resolver),
            graph_head=cast(Any, fixture.graph_head),
            campaign=fixture.campaign,
        )
    assert fixture.seam_calls == []

    caller = cast(Any, prepare_agentic_specialist_action)
    for extra in (
        {"profile": object()},
        {"executor": object()},
        {"transport": object()},
        {"payload": object()},
    ):
        with pytest.raises(TypeError, match="unexpected keyword"):
            caller(
                store=fixture.store,
                reservation=fixture.reservation,
                graph_resolver=fixture.graph_resolver,
                graph_head=fixture.graph_head,
                campaign=fixture.campaign,
                **extra,
            )
    assert fixture.seam_calls == []


def test_stale_or_consumed_reservation_fails_before_route_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(
        monkeypatch,
        seam_error=AgenticCoordinationError("reservation is stale or consumed"),
    )

    def forbidden_route_resolution() -> object:
        raise AssertionError("route resolution must not follow reservation rejection")

    monkeypatch.setattr(
        specialist_preparation,
        "production_governed_web_adapter_profile_registry",
        forbidden_route_resolution,
    )
    monkeypatch.setattr(
        specialist_preparation,
        "production_web_specialist_execution_profile_catalog",
        forbidden_route_resolution,
    )
    monkeypatch.setattr(
        specialist_preparation,
        "production_web_specialist_executor_catalog",
        forbidden_route_resolution,
    )

    with pytest.raises(AgenticSpecialistPreparationError, match="live store-local"):
        _prepare(fixture)
    assert len(fixture.seam_calls) == 1


def test_nonreserved_seam_entry_fails_before_route_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    drifted = fixture.entry.model_copy(
        update={"state": AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN}
    )

    def return_nonreserved_entry(
        observed_store: AgenticCoordinationStore,
        observed_reservation: VerifiedSpecialistExecutionReservation,
        *,
        graph_resolver: object,
        graph_head: object,
    ) -> AgenticSpecialistExecutionEntry:
        assert observed_store is fixture.store
        assert observed_reservation is fixture.reservation
        assert graph_resolver is fixture.graph_resolver
        assert graph_head is fixture.graph_head
        return drifted

    def forbidden_route_resolution() -> object:
        raise AssertionError("route resolution must not follow a nonreserved entry")

    monkeypatch.setattr(
        AgenticCoordinationStore,
        "specialist_preparation_entry",
        return_nonreserved_entry,
    )
    monkeypatch.setattr(
        specialist_preparation,
        "production_governed_web_adapter_profile_registry",
        forbidden_route_resolution,
    )

    with pytest.raises(AgenticSpecialistPreparationError, match="not reserved"):
        _prepare(fixture)


@pytest.mark.parametrize("mutation", ["target", "scope"])
def test_campaign_target_and_scope_must_match_code_owned_route_even_when_bound(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    wire = _governed_campaign().model_dump(mode="json", by_alias=True)
    if mutation == "target":
        cast(list[dict[str, object]], wire["spec"]["targets"])[0]["endpoint"] = (
            "http://127.0.0.1:3002"
        )
    else:
        cast(dict[str, object], wire["spec"])["scope"] = {
            "allow": [GOVERNED_JUICE_SHOP_ORIGIN + "/api/**"],
            "deny": [],
        }
    campaign = CampaignManifest.model_validate(wire)
    fixture = _fixture(monkeypatch, campaign=campaign)

    expected = "target differs" if mutation == "target" else "Scope differs"
    with pytest.raises(AgenticSpecialistPreparationError, match=expected):
        _prepare(fixture)


def test_campaign_budget_digest_must_match_coordination_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    wire = fixture.campaign.model_dump(mode="json", by_alias=True)
    cast(dict[str, object], cast(dict[str, object], wire["spec"])["budgets"])["maxToolCalls"] = 3
    changed = CampaignManifest.model_validate(wire)

    with pytest.raises(AgenticSpecialistPreparationError, match="Campaign identity"):
        _prepare(fixture, campaign=changed)
    assert len(fixture.seam_calls) == 1


def test_unsupported_assignment_route_has_no_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(
        monkeypatch,
        specialization=PentestSpecialization.SSRF,
        threat_class="ssrf",
    )

    with pytest.raises(AgenticSpecialistPreparationError, match="code-owned route"):
        _prepare(fixture)
    assert len(fixture.seam_calls) == 1
