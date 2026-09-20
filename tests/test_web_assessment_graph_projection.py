from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.capabilities.web_browser_assessment import WEB_BROWSER_ASSESSMENT_ORIGIN
from pajin.graph.admission import (
    GraphAdmissionAuthority,
    GraphAdmissionDecision,
    GraphAdmissionReason,
    GraphProducerRegistration,
    GraphProducerRegistry,
    InMemoryGraphEventLog,
    TrustedGraphLineageRegistry,
)
from pajin.graph.models import (
    GraphActionStatus,
    GraphAuthorityKind,
    GraphContentOrigin,
    GraphProposalKind,
    HypothesisProposal,
    ObservationProposal,
)
from pajin.web_assessment.browser import BrowserAssessmentObservation, BrowserCredentials
from pajin.web_assessment.campaign import (
    LocalWebAssessmentCampaignDraft,
    LocalWebAssessmentRunReference,
    build_local_web_assessment_campaign_draft,
    local_web_assessment_run_reference,
)
from pajin.web_assessment.diagnostic_catalog import _testing_diagnostic_bundle_catalog
from pajin.web_assessment.graph_projection import (
    LocalWebNeutralGraphProjection,
    LocalWebNeutralGraphProjectionError,
    LocalWebSealedSourceAuthority,
    build_local_web_neutral_graph_projection,
    build_local_web_sealed_source_authority,
)
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import (
    issue_local_web_assessment_authorization,
    provision_local_web_assessment_account,
    run_local_web_assessment,
)
from pajin.web_assessment.verification import (
    VerifiedLocalWebAssessmentSourceIntegrity,
    load_verified_local_web_assessment_source_integrity,
)
from tests.test_web_assessment import _FakeBrowser, _mock_transport


class _SemanticFakeBrowser(_FakeBrowser):
    async def run(self, credentials: BrowserCredentials) -> BrowserAssessmentObservation:
        observed = await super().run(credentials)
        trials = tuple(
            trial.model_copy(
                update={
                    "facts": {
                        "controlMarkerExecuted": False,
                        "probeMarkerExecuted": True,
                        "externalTransmission": False,
                    }
                }
            )
            for trial in observed.dom_xss_trials
        )
        return replace(observed, dom_xss_trials=(trials[0], trials[1]))


type ProjectionMaterial = tuple[
    LocalWebAssessmentCampaignDraft,
    LocalWebAssessmentRunReference,
    VerifiedLocalWebAssessmentSourceIntegrity,
    LocalWebSealedSourceAuthority,
]


@pytest.fixture
def projection_material(tmp_path: Path) -> ProjectionMaterial:
    async def create_source() -> VerifiedLocalWebAssessmentSourceIntegrity:
        plan = juice_shop_plan(WEB_BROWSER_ASSESSMENT_ORIGIN)
        authorization = issue_local_web_assessment_authorization(
            plan,
            operator_confirmed_authorized_local_lab=True,
        )
        transport = _mock_transport(plan, [])
        account = await provision_local_web_assessment_account(
            plan=plan,
            authorization=authorization,
            network_factory=lambda selected: AssessmentNetwork(
                selected,
                transport=transport,
            ),
        )
        artifacts = await run_local_web_assessment(
            plan=plan,
            authorization=authorization,
            output_root=tmp_path,
            browser_factory=_SemanticFakeBrowser,
            network_factory=lambda selected: AssessmentNetwork(
                selected,
                transport=transport,
            ),
            provisioned_account=account,
            diagnostic_catalog=_testing_diagnostic_bundle_catalog(),
        )
        return load_verified_local_web_assessment_source_integrity(
            artifacts.run_path,
            expected_run_id=artifacts.result.run_id,
            expected_root_digest=artifacts.root_digest,
        )

    source = asyncio.run(create_source())
    draft = build_local_web_assessment_campaign_draft(
        source.plan,
        source.authorization,
        evaluated_at=source.result.started_at,
    )
    run_reference = local_web_assessment_run_reference(
        role="source",
        verified_source=source,
    )
    authority = build_local_web_sealed_source_authority(
        draft=draft,
        run_reference=run_reference,
        source=source,
        source_identity_pin_independently_supplied=False,
    )
    return draft, run_reference, source, authority


def _build(material: ProjectionMaterial) -> LocalWebNeutralGraphProjection:
    draft, run_reference, source, authority = material
    return build_local_web_neutral_graph_projection(
        source_authority=authority,
        draft=draft,
        run_reference=run_reference,
        source=source,
    )


def test_projection_builds_only_sealed_source_neutral_proposals(
    projection_material: ProjectionMaterial,
) -> None:
    draft, run_reference, source, authority = projection_material
    projection = _build(projection_material)

    assert isinstance(projection.observation_proposal, ObservationProposal)
    assert all(
        isinstance(proposal, HypothesisProposal) for proposal in projection.hypothesis_proposals
    )
    assert len(projection.hypothesis_proposals) == 3
    assert projection.source_authority == authority
    assert authority.campaign_draft_id == draft.draft_id
    assert authority.run_reference_digest == run_reference.reference_digest
    assert authority.source_root_digest == source.verification.root_digest
    assert authority.source_identity_pin_independently_supplied is False
    assert authority.independent_execution_attested is False
    assert authority.finding_authority is False
    assert authority.sarif_authority is False
    assert authority.graph_admission_performed is False

    observation = projection.observation_proposal
    assert observation.action.authority_kind is GraphAuthorityKind.SEALED_SOURCE_AUTHORITY
    assert observation.action.authority_id == authority.authority_id
    assert observation.action.authority_digest == authority.authority_digest
    assert observation.action.status is GraphActionStatus.SUCCEEDED
    assert observation.action.capability_id is None
    assert observation.action.capability_version is None
    assert observation.action.capability_digest is None
    assert observation.observation.origin is GraphContentOrigin.TARGET_DERIVED
    for proposal in (observation, *projection.hypothesis_proposals):
        assert proposal.lineage.source_authority_id == authority.authority_id
        assert proposal.lineage.source_authority_digest == authority.authority_digest
        assert proposal.lineage.capability_grant_id is None
        assert proposal.lineage.action_permit_id is None
        assert proposal.lineage.capability_id is None

    serialized = json.dumps(
        projection.model_dump(mode="json", by_alias=True, exclude_none=True),
        sort_keys=True,
    )
    for forbidden in (
        "CampaignManifest",
        "actionPermitId",
        "actionPermitDigest",
        "approvalReceipt",
        "capabilityGrantId",
        "capabilityId",
    ):
        assert forbidden not in serialized


def test_projection_does_not_admit_graph_or_mint_finding_authority(
    projection_material: ProjectionMaterial,
) -> None:
    projection = _build(projection_material)

    assert projection.semantics == "neutral-sealed-source-observation-only"
    assert projection.independent_execution_attested is False
    assert projection.finding_authority is False
    assert projection.sarif_authority is False
    assert projection.graph_admission_performed is False
    assert all(
        proposal.hypothesis.confidence == 0.25
        and "requires separately authorized independent execution" in proposal.hypothesis.statement
        for proposal in projection.hypothesis_proposals
    )


def test_neutral_observation_requires_separately_registered_lineage_for_admission(
    projection_material: ProjectionMaterial,
) -> None:
    proposal = _build(projection_material).observation_proposal
    event_log = InMemoryGraphEventLog()
    authority = GraphAdmissionAuthority(
        campaign_id=proposal.lineage.campaign_id,
        authority_id="pajin.graph.web004-admission-test",
        authority_digest="a" * 64,
        producers=GraphProducerRegistry(
            (
                GraphProducerRegistration(
                    producerId=proposal.producer_id,
                    producerVersion=proposal.producer_version,
                    producerDigest=proposal.producer_digest,
                    allowedProposalKinds=(GraphProposalKind.OBSERVATION,),
                ),
            )
        ),
        lineage_verifier=TrustedGraphLineageRegistry(),
        event_log=event_log,
        clock=lambda: proposal.lineage.produced_at + timedelta(seconds=1),
    )

    result = authority.submit(proposal)

    assert result.event.decision is GraphAdmissionDecision.REJECTED
    assert result.event.reason is GraphAdmissionReason.LINEAGE_VERIFICATION_FAILED
    assert result.event.admitted_nodes == []
    assert result.event.admitted_edges == []


def test_neutral_observation_rejects_mixed_or_relabelled_permit_lineage(
    projection_material: ProjectionMaterial,
) -> None:
    proposal = _build(projection_material).observation_proposal
    mixed = proposal.model_dump(mode="json", by_alias=True)
    mixed["lineage"]["actionPermitId"] = "action-permit_web004-forged"
    mixed["lineage"]["actionPermitDigest"] = "b" * 64
    with pytest.raises(ValidationError, match="cannot claim Capability or Permit"):
        ObservationProposal.model_validate(mixed)

    relabelled = proposal.model_dump(mode="json", by_alias=True)
    relabelled["lineage"].pop("sourceAuthorityId")
    relabelled["lineage"].pop("sourceAuthorityDigest")
    relabelled["lineage"].update(
        {
            "actionPermitId": "action-permit_web004-forged",
            "actionPermitDigest": "b" * 64,
            "capabilityId": "pajin.bug-bounty.web-browser-assessment",
            "capabilityVersion": "1.0.0",
            "capabilityDigest": "c" * 64,
        }
    )
    with pytest.raises(ValidationError, match="differs from its request lineage"):
        ObservationProposal.model_validate(relabelled)


@pytest.mark.parametrize(
    "field",
    (
        "independentExecutionAttested",
        "findingAuthority",
        "sarifAuthority",
        "graphAdmissionPerformed",
    ),
)
def test_source_authority_rejects_downstream_authority_markers(
    projection_material: ProjectionMaterial,
    field: str,
) -> None:
    *_, authority = projection_material
    raw = authority.model_dump(mode="json", by_alias=True)
    raw.pop("authorityId")
    raw.pop("authorityDigest")
    raw[field] = True

    with pytest.raises(ValidationError, match="cannot claim downstream authority"):
        LocalWebSealedSourceAuthority.model_validate(raw)


@pytest.mark.parametrize(
    "field",
    (
        "independentExecutionAttested",
        "findingAuthority",
        "sarifAuthority",
        "graphAdmissionPerformed",
    ),
)
def test_projection_rejects_downstream_authority_markers(
    projection_material: ProjectionMaterial,
    field: str,
) -> None:
    projection = _build(projection_material)
    raw = projection.model_dump(mode="json", by_alias=True)
    raw.pop("projectionDigest")
    raw[field] = True

    with pytest.raises(ValidationError, match="authority markers"):
        LocalWebNeutralGraphProjection.model_validate(raw)


def test_source_pin_disclosure_is_strict_and_does_not_change_authority_kind(
    projection_material: ProjectionMaterial,
) -> None:
    draft, run_reference, source, authority = projection_material
    raw = authority.model_dump(mode="json", by_alias=True)
    raw.pop("authorityId")
    raw.pop("authorityDigest")
    raw["sourceIdentityPinIndependentlySupplied"] = "false"
    with pytest.raises(ValidationError):
        LocalWebSealedSourceAuthority.model_validate(raw)

    independently_pinned = build_local_web_sealed_source_authority(
        draft=draft,
        run_reference=run_reference,
        source=source,
        source_identity_pin_independently_supplied=True,
    )
    projection = build_local_web_neutral_graph_projection(
        source_authority=independently_pinned,
        draft=draft,
        run_reference=run_reference,
        source=source,
    )
    assert independently_pinned.source_identity_pin_independently_supplied is True
    assert projection.observation_proposal.action.authority_kind is (
        GraphAuthorityKind.SEALED_SOURCE_AUTHORITY
    )
    assert projection.independent_execution_attested is False


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("campaign_draft_digest", "0" * 64),
        ("run_reference_digest", "0" * 64),
        ("source_root_digest", "0" * 64),
        ("result_digest", "0" * 64),
        ("source_plan_digest", "0" * 64),
        ("semantic_claims_digest", "0" * 64),
        ("request_digest", "0" * 64),
        ("target_digest", "0" * 64),
        ("authority_digest", "0" * 64),
    ),
)
def test_projection_rejects_tampered_source_authority_pins(
    projection_material: ProjectionMaterial,
    field: str,
    value: str,
) -> None:
    draft, run_reference, source, authority = projection_material
    tampered = authority.model_copy(update={field: value})

    with pytest.raises(LocalWebNeutralGraphProjectionError):
        build_local_web_neutral_graph_projection(
            source_authority=tampered,
            draft=draft,
            run_reference=run_reference,
            source=source,
        )


def test_projection_rejects_foreign_draft_and_run_reference(
    projection_material: ProjectionMaterial,
) -> None:
    draft, run_reference, source, authority = projection_material
    later_draft = build_local_web_assessment_campaign_draft(
        source.plan,
        source.authorization,
        evaluated_at=draft.evaluated_at + timedelta(milliseconds=1),
    )
    tampered_reference = run_reference.model_copy(update={"root_digest": "0" * 64})

    with pytest.raises(LocalWebNeutralGraphProjectionError):
        build_local_web_neutral_graph_projection(
            source_authority=authority,
            draft=later_draft,
            run_reference=run_reference,
            source=source,
        )
    with pytest.raises(LocalWebNeutralGraphProjectionError):
        build_local_web_neutral_graph_projection(
            source_authority=authority,
            draft=draft,
            run_reference=tampered_reference,
            source=source,
        )


def test_projection_reloads_and_rejects_changed_source_bytes(
    projection_material: ProjectionMaterial,
) -> None:
    draft, run_reference, source, authority = projection_material
    report_path = source.run_path / "report.md"
    report_path.write_text(report_path.read_text() + "tampered\n")

    with pytest.raises(LocalWebNeutralGraphProjectionError):
        build_local_web_neutral_graph_projection(
            source_authority=authority,
            draft=draft,
            run_reference=run_reference,
            source=source,
        )
