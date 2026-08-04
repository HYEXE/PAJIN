from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.domain.models import CampaignManifest
from pajin.graph import (
    CampaignFactPayload,
    CampaignFactProposal,
    CampaignFactValidationState,
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionReason,
    GraphContentOrigin,
    GraphEvidenceBinding,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProposalKind,
    GraphProposalLineage,
    InMemoryGraphEventLog,
    SealedCampaignFactAdmissionError,
    SealedRunCampaignFactAdapter,
    TrustedGraphLineageRegistry,
)
from pajin.runtime.store import RunStore, load_verified_run_artifacts

NOW = datetime(2026, 8, 2, 3, 0, tzinfo=UTC)
PRODUCER_ID = "pajin.memory.test-fact-producer"
PRODUCER_VERSION = "1.0.0"
PRODUCER_DIGEST = "a" * 64
REQUEST_DIGEST = "b" * 64
GRANT_DIGEST = "c" * 64
CAPABILITY_DIGEST = "d" * 64
EVIDENCE_REFERENCE = "evidence/campaign-fact-source.json"
EVIDENCE = b'{"observation":"bounded shared fact"}\n'


def _sealed_source(
    tmp_path: Path,
    campaign: CampaignManifest,
    *,
    run_id: str | None = None,
) -> RunStore:
    store = RunStore.create(
        tmp_path / "runs",
        campaign.metadata.name,
        run_id=run_id,
    )
    store.append_event(
        "campaign.started",
        {"campaign": campaign.metadata.name, "mode": campaign.spec.mode.value},
        occurred_at=NOW,
    )
    store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))
    store.write_bytes(EVIDENCE_REFERENCE, EVIDENCE)
    store.seal()
    return store


def _proposal(store: RunStore, campaign_id: str) -> CampaignFactProposal:
    snapshot = load_verified_run_artifacts(
        store.path,
        requests={EVIDENCE_REFERENCE: 1024},
        expected_run_id=store.run_id,
    )
    return CampaignFactProposal(
        proposalId="proposal:campaign-fact:1",
        producerId=PRODUCER_ID,
        producerVersion=PRODUCER_VERSION,
        producerDigest=PRODUCER_DIGEST,
        lineage=GraphProposalLineage(
            campaignId=campaign_id,
            runId=store.run_id,
            agentId="agent:fact-producer",
            taskId="task:fact-proposal:1",
            requestId="request_fact_1",
            requestDigest=REQUEST_DIGEST,
            capabilityGrantId="grant:fact-proposal:1",
            capabilityGrantDigest=GRANT_DIGEST,
            capabilityId="pajin.graph.propose-campaign-fact",
            capabilityVersion="1.0.0",
            capabilityDigest=CAPABILITY_DIGEST,
            sourceRootDigest=snapshot.verification.root_digest,
            evidence=[
                GraphEvidenceBinding(
                    reference=EVIDENCE_REFERENCE,
                    sha256=sha256(EVIDENCE).hexdigest(),
                )
            ],
            producedAt=NOW + timedelta(seconds=3),
        ),
        fact=CampaignFactPayload(
            factKey="target.security-control",
            statement="The observed target exposes the recorded security-control state.",
            valueDigest=sha256(b"security-control-state").hexdigest(),
            producerId=PRODUCER_ID,
            producerVersion=PRODUCER_VERSION,
            producerDigest=PRODUCER_DIGEST,
            origin=GraphContentOrigin.TARGET_DERIVED,
            recordedAt=NOW + timedelta(seconds=1),
        ),
    )


def _adapter(
    proposal: CampaignFactProposal,
) -> tuple[SealedRunCampaignFactAdapter, InMemoryGraphEventLog]:
    event_log = InMemoryGraphEventLog()
    authority = GraphAdmissionAuthority(
        campaign_id=proposal.lineage.campaign_id,
        authority_id="pajin.graph.campaign-fact-admission",
        authority_digest="e" * 64,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId=PRODUCER_ID,
                    producerVersion=PRODUCER_VERSION,
                    producerDigest=PRODUCER_DIGEST,
                    allowedProposalKinds=(GraphProposalKind.CAMPAIGN_FACT,),
                )
            ]
        ),
        lineage_verifier=TrustedGraphLineageRegistry([proposal.lineage]),
        event_log=event_log,
        clock=lambda: NOW + timedelta(seconds=4),
    )
    return SealedRunCampaignFactAdapter(authority), event_log


def test_adapter_admits_existing_fact_as_immutable_non_executable_record(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    proposal = _proposal(source, sample_campaign.metadata.name)
    adapter, event_log = _adapter(proposal)

    first = adapter.submit(proposal, source_run_path=source.path)
    retry = adapter.submit(proposal, source_run_path=source.path)

    assert first.event.decision is GraphAdmissionDecision.ADMITTED
    assert retry.event == first.event
    assert retry.idempotent is True
    assert len(event_log.events()) == 1
    assert first.event.campaign_id == sample_campaign.metadata.name
    assert first.event.run_id == source.run_id
    assert first.event.source_root_digest == proposal.lineage.source_root_digest
    assert first.event.producer_id == PRODUCER_ID
    assert first.event.producer_version == PRODUCER_VERSION
    assert first.event.producer_digest == PRODUCER_DIGEST
    assert first.event.evidence == proposal.lineage.evidence
    fact = first.event.admitted_nodes[0]
    assert fact.validation_state is CampaignFactValidationState.ADMITTED
    assert fact.origin is GraphContentOrigin.TARGET_DERIVED
    assert {
        "command",
        "prompt",
        "messages",
        "scope",
        "toolRequest",
        "capabilityGrant",
        "actionPermit",
        "executionAuthorized",
    }.isdisjoint(fact.model_dump(mode="json", by_alias=True))


@pytest.mark.parametrize("mutation", ["evidence", "root"])
def test_adapter_rejects_forged_evidence_or_stale_source_before_graph_append(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    mutation: str,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    proposal = _proposal(source, sample_campaign.metadata.name)
    if mutation == "evidence":
        proposal.lineage.evidence[0].sha256 = "f" * 64
    else:
        source.append_event("campaign.fact_source.extended", {"reason": "new evidence"})
        source.seal()
    adapter, event_log = _adapter(proposal)

    with pytest.raises(SealedCampaignFactAdmissionError):
        adapter.submit(proposal, source_run_path=source.path)

    assert event_log.events() == ()


def test_adapter_rejects_cross_campaign_and_cross_run_substitution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    proposal = _proposal(source, sample_campaign.metadata.name)
    adapter, event_log = _adapter(proposal)

    foreign_campaign = sample_campaign.model_copy(deep=True)
    foreign_campaign.metadata.name = "foreign-campaign"
    foreign = _sealed_source(
        tmp_path / "foreign",
        foreign_campaign,
        run_id=source.run_id,
    )
    with pytest.raises(SealedCampaignFactAdmissionError):
        adapter.submit(proposal, source_run_path=foreign.path)

    other_run = _sealed_source(tmp_path / "other", sample_campaign)
    with pytest.raises(SealedCampaignFactAdmissionError):
        adapter.submit(proposal, source_run_path=other_run.path)

    assert event_log.events() == ()


def test_full_lineage_and_producer_authorities_remain_independent_gates(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    trusted = _proposal(source, sample_campaign.metadata.name)
    adapter, event_log = _adapter(trusted)
    forged = trusted.model_copy(deep=True)
    forged.proposal_id = "proposal:campaign-fact:forged-lineage"
    forged.lineage.capability_digest = "f" * 64

    rejected = adapter.submit(forged, source_run_path=source.path)

    assert rejected.event.decision is GraphAdmissionDecision.REJECTED
    assert rejected.event.reason is GraphAdmissionReason.LINEAGE_VERIFICATION_FAILED
    assert rejected.event.admitted_nodes == []
    assert len(event_log.events()) == 1


def test_registered_producer_contract_remains_an_independent_gate(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    trusted = _proposal(source, sample_campaign.metadata.name)
    adapter, event_log = _adapter(trusted)
    forged = trusted.model_copy(deep=True)
    forged.proposal_id = "proposal:campaign-fact:forged-producer"
    forged.producer_version = "2.0.0"
    forged.fact.producer_version = "2.0.0"

    rejected = adapter.submit(forged, source_run_path=source.path)

    assert rejected.event.decision is GraphAdmissionDecision.REJECTED
    assert rejected.event.reason is GraphAdmissionReason.PRODUCER_CONTRACT_MISMATCH
    assert rejected.event.admitted_nodes == []
    assert len(event_log.events()) == 1


def test_agent_cannot_forge_campaign_fact_validation_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    proposal = _proposal(source, sample_campaign.metadata.name)
    raw = proposal.model_dump(mode="json", by_alias=True)
    raw["fact"]["validationState"] = CampaignFactValidationState.ADMITTED.value

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CampaignFactProposal.model_validate(raw)


def test_same_id_different_fact_is_audited_as_equivocation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source = _sealed_source(tmp_path, sample_campaign)
    proposal = _proposal(source, sample_campaign.metadata.name)
    adapter, event_log = _adapter(proposal)
    assert adapter.submit(proposal, source_run_path=source.path).event.decision is (
        GraphAdmissionDecision.ADMITTED
    )
    equivocated = proposal.model_copy(deep=True)
    equivocated.fact.statement = "A conflicting statement reuses the same proposal identity."
    equivocated.fact.value_digest = sha256(b"conflicting-value").hexdigest()

    rejected = adapter.submit(equivocated, source_run_path=source.path)

    assert rejected.event.decision is GraphAdmissionDecision.REJECTED
    assert rejected.event.reason is GraphAdmissionReason.PROPOSAL_EQUIVOCATION
    assert len(event_log.events()) == 2
