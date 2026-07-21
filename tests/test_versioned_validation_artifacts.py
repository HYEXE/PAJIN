from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.domain.models import Finding, FindingSeverity
from pajin.domain.validation import (
    CandidateFinding,
    ConfirmationBasis,
    FindingDisposition,
    FindingValidationSet,
    ReplayConfirmationLineage,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
    VersionedConfirmedFindingSet,
    VersionedValidationDecisionSet,
    VersionedValidationIndex,
)
from pajin.runtime.store import RunIntegritySeal, RunStore, load_verified_run_snapshot
from pajin.workflow.validation_artifacts import (
    VERSIONED_VALIDATION_DECISIONS_PATH,
    VERSIONED_VALIDATION_FINDINGS_PATH,
    VERSIONED_VALIDATION_INDEX_PATH,
    VERSIONED_VALIDATION_REPORT_PATH,
    ValidationSnapshotSemantics,
    load_source_validation_artifacts,
    load_validation_snapshot,
    write_validation_artifacts,
)

NOW = datetime(2026, 7, 16, 9, 0, tzinfo=UTC)


def _finding(*, validated: bool = False) -> Finding:
    return Finding(
        finding_id="finding_versioned_1",
        title="Versioned validation boundary",
        severity=FindingSeverity.HIGH,
        threat_class="M03",
        target="https://target.example/v1/chat",
        summary="A bounded claim used to exercise validation artifact loading.",
        reproduction=["Replay the authorized request in a fresh session."],
        evidence=[],
        confidence=0.9,
        validated=validated,
    )


def _candidate() -> CandidateFinding:
    return CandidateFinding(
        candidate_id="candidate_versioned_1",
        claim=_finding(),
        source="trusted-core:candidate-producer",
        source_agent_id="trusted-core:test-producer",
        source_request_ids=["request_source_1"],
        created_at=NOW,
    )


def _source_decision(
    *,
    disposition: FindingDisposition,
) -> ValidationDecision:
    confirmed = disposition is FindingDisposition.CONFIRMED
    return ValidationDecision(
        decision_id="decision_source_1",
        candidate_id="candidate_versioned_1",
        validator_id="agent:semantic-validator:1",
        method=ValidationMethod.HYBRID_LEGACY_GATE,
        disposition=disposition,
        reason_codes=[
            (
                ValidationReasonCode.VALIDATOR_CONFIRMED
                if confirmed
                else ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING
            )
        ],
        decision_summary=(
            "Legacy semantic validation confirmed the claim."
            if confirmed
            else "Independent reproduction has not run."
        ),
        supporting_evidence=[],
        contradicting_evidence=[],
        replay_request_ids=[],
        checks=[],
        decided_at=NOW,
    )


def _sealed_source_run(
    tmp_path: Path,
    *,
    legacy_confirmed: bool,
) -> tuple[RunStore, CandidateFinding, ValidationDecision, Finding, RunIntegritySeal]:
    store = RunStore.create(tmp_path, "versioned-validation-test")
    candidate = _candidate()
    source_decision = _source_decision(
        disposition=(
            FindingDisposition.CONFIRMED if legacy_confirmed else FindingDisposition.NEEDS_REVIEW
        )
    )
    confirmed_finding = candidate.claim.model_copy(update={"validated": True})
    validation = FindingValidationSet(
        candidates=[candidate],
        decisions=[source_decision],
        confirmed_findings=[confirmed_finding] if legacy_confirmed else [],
    )

    store.append_event("test.source-validation.created", {"legacy": legacy_confirmed})
    write_validation_artifacts(store, validation)
    store.write_json(
        "findings.json",
        [confirmed_finding.model_dump(mode="json")] if legacy_confirmed else [],
    )
    source_seal = store.seal()
    return store, candidate, source_decision, confirmed_finding, source_seal


def _lineage(candidate_source_root_digest: str) -> ReplayConfirmationLineage:
    return ReplayConfirmationLineage(
        replay_run_id="run_replay_versioned_1",
        replay_outcome_id="replay-outcome_versioned_1",
        replay_request_ids=["request_replay_1"],
        replay_evidence=["evidence/request_replay_1.json"],
        oracle_result_id="oracle-result_versioned_1",
        ticket_id="ticket_versioned_1",
        candidate_source_root_digest=candidate_source_root_digest,
        artifact_set_digest="a" * 64,
        artifact_seal_root_digest="b" * 64,
        receipt_seal_root_digest="c" * 64,
        verified_at=NOW,
    )


def _confirmed_decision(
    source_decision: ValidationDecision,
    lineage: ReplayConfirmationLineage,
    *,
    supersedes_decision_id: str | None = None,
) -> ValidationDecision:
    return ValidationDecision(
        decision_id="decision_replay_1",
        supersedes_decision_id=supersedes_decision_id or source_decision.decision_id,
        candidate_id=source_decision.candidate_id,
        validator_id="trusted-core:confirmed-gate",
        method=ValidationMethod.RESTRICTED_REPLAY_GATE,
        disposition=FindingDisposition.CONFIRMED,
        confirmation_basis=ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY,
        reason_codes=[ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED],
        decision_summary="A verified independent replay supported the exact claim.",
        supporting_evidence=[],
        contradicting_evidence=[],
        replay_request_ids=lineage.replay_request_ids,
        replay_outcome_ids=[lineage.replay_outcome_id],
        replay_lineage=[lineage],
        checks=[],
        decided_at=NOW,
    )


def _write_versioned_projection(
    store: RunStore,
    *,
    candidate: CandidateFinding,
    source_decision: ValidationDecision,
    source_root_digest: str,
) -> tuple[ValidationDecision, VersionedValidationIndex]:
    lineage = _lineage(source_root_digest)
    decision = _confirmed_decision(source_decision, lineage)
    confirmed_finding = candidate.claim.model_copy(update={"validated": True})
    index = VersionedValidationIndex(
        source_run_id=store.run_id,
        candidate_source_root_digest=source_root_digest,
        confirmation_semantics="verified-independent-replay",
        dispositions={
            FindingDisposition.CONFIRMED: [candidate.candidate_id],
            FindingDisposition.NEEDS_REVIEW: [],
            FindingDisposition.INCONCLUSIVE: [],
            FindingDisposition.REJECTED_OBJECTIVE: [],
        },
        confirmed_candidate_ids=[candidate.candidate_id],
        generated_at=NOW,
    )
    decision_set = VersionedValidationDecisionSet(
        source_run_id=store.run_id,
        decisions=[decision],
    )
    finding_set = VersionedConfirmedFindingSet(
        source_run_id=store.run_id,
        confirmation_semantics="verified-independent-replay",
        findings=[confirmed_finding],
    )

    store.write_json(
        VERSIONED_VALIDATION_DECISIONS_PATH,
        decision_set.model_dump(mode="json", by_alias=True),
    )
    store.write_json(
        VERSIONED_VALIDATION_FINDINGS_PATH,
        finding_set.model_dump(mode="json", by_alias=True),
    )
    store.write_text(VERSIONED_VALIDATION_REPORT_PATH, "# Reproduction-backed report\n")
    store.write_json(
        VERSIONED_VALIDATION_INDEX_PATH,
        index.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "test.versioned-validation.created",
        {"index": VERSIONED_VALIDATION_INDEX_PATH},
    )
    store.seal()
    return decision, index


def test_sealed_flat_legacy_confirmation_is_not_product_confirmation(
    tmp_path: Path,
) -> None:
    store, _, source_decision, confirmed_finding, _ = _sealed_source_run(
        tmp_path,
        legacy_confirmed=True,
    )

    raw = load_source_validation_artifacts(store.path)
    loaded = load_validation_snapshot(store.path)

    assert raw.confirmed_findings == [confirmed_finding]
    assert raw.decisions == [source_decision]
    assert raw.decisions[0].confirmation_basis is None
    assert loaded.validation == raw
    assert loaded.semantics is ValidationSnapshotSemantics.LEGACY_UNVERSIONED
    assert loaded.product_confirmed_findings == []


def test_validation_loaders_reject_a_later_run_phase_than_the_authority_snapshot(
    tmp_path: Path,
) -> None:
    store, *_ = _sealed_source_run(tmp_path, legacy_confirmed=False)
    authority = load_verified_run_snapshot(store.path)
    store.write_json("later-phase.json", {"phase": "later"})
    store.append_event("test.later-phase.created", {"phase": "later"})
    store.seal()

    with pytest.raises(ValueError, match="validation Run changed"):
        load_source_validation_artifacts(
            store.path,
            verified_snapshot=authority,
        )
    with pytest.raises(ValueError, match="validation Run changed"):
        load_validation_snapshot(
            store.path,
            verified_snapshot=authority,
        )
    for loader in (load_source_validation_artifacts, load_validation_snapshot):
        with pytest.raises(ValueError, match="root digest differs"):
            loader(
                store.path,
                expected_run_id=authority.verification.run_id,
                expected_root_digest=authority.verification.root_digest,
            )


def test_partial_versioned_projection_without_index_fails_closed(
    tmp_path: Path,
) -> None:
    store, _, _, _, _ = _sealed_source_run(tmp_path, legacy_confirmed=True)
    store.write_json(
        VERSIONED_VALIDATION_DECISIONS_PATH,
        {"partial": "must not fall back to the legacy confirmed projection"},
    )
    store.append_event(
        "test.partial-versioned-validation.created",
        {"artifact": VERSIONED_VALIDATION_DECISIONS_PATH},
    )
    store.seal()

    with pytest.raises(ValueError, match="exist without their index"):
        load_validation_snapshot(store.path)


def test_versioned_projection_cannot_launder_a_legacy_flat_confirmation(
    tmp_path: Path,
) -> None:
    store, candidate, source_decision, _, source_seal = _sealed_source_run(
        tmp_path,
        legacy_confirmed=True,
    )
    _write_versioned_projection(
        store,
        candidate=candidate,
        source_decision=source_decision,
        source_root_digest=source_seal.root_digest,
    )

    with pytest.raises(ValueError, match="requires an unreproduced source snapshot"):
        load_validation_snapshot(store.path)


def test_valid_versioned_projection_enforces_fixed_paths_and_receipt_lineage(
    tmp_path: Path,
) -> None:
    store, candidate, source_decision, confirmed_finding, source_seal = _sealed_source_run(
        tmp_path,
        legacy_confirmed=False,
    )
    final_decision, index = _write_versioned_projection(
        store,
        candidate=candidate,
        source_decision=source_decision,
        source_root_digest=source_seal.root_digest,
    )

    loaded = load_validation_snapshot(store.path)

    assert loaded.semantics is ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY
    assert loaded.product_confirmed_findings == [confirmed_finding]
    assert loaded.validation.decisions == [final_decision]
    assert loaded.index == index
    assert loaded.index is not None
    assert loaded.index.candidate_findings_path == "candidate-findings.json"
    assert loaded.index.decisions_path == VERSIONED_VALIDATION_DECISIONS_PATH
    assert loaded.index.findings_path == VERSIONED_VALIDATION_FINDINGS_PATH
    assert loaded.index.report_path == VERSIONED_VALIDATION_REPORT_PATH
    assert final_decision.replay_lineage[0].candidate_source_root_digest == (
        source_seal.root_digest
    )

    substituted_index = index.model_dump(mode="json", by_alias=True)
    substituted_index["decisionsPath"] = "validation/v1alpha1/substituted.json"
    with pytest.raises(ValidationError):
        VersionedValidationIndex.model_validate(substituted_index)

    substituted_decision = final_decision.model_dump(mode="python")
    substituted_decision["replay_request_ids"] = ["request_substituted"]
    with pytest.raises(ValidationError, match="exactly match replay lineage"):
        ValidationDecision.model_validate(substituted_decision)


def test_versioned_projection_rejects_substituted_source_supersession(
    tmp_path: Path,
) -> None:
    store, candidate, source_decision, _, source_seal = _sealed_source_run(
        tmp_path,
        legacy_confirmed=False,
    )
    lineage = _lineage(source_seal.root_digest)
    substituted = _confirmed_decision(
        source_decision,
        lineage,
        supersedes_decision_id="decision_unrelated_source",
    )
    confirmed_finding = candidate.claim.model_copy(update={"validated": True})
    index = VersionedValidationIndex(
        source_run_id=store.run_id,
        candidate_source_root_digest=source_seal.root_digest,
        confirmation_semantics="verified-independent-replay",
        dispositions={
            FindingDisposition.CONFIRMED: [candidate.candidate_id],
            FindingDisposition.NEEDS_REVIEW: [],
            FindingDisposition.INCONCLUSIVE: [],
            FindingDisposition.REJECTED_OBJECTIVE: [],
        },
        confirmed_candidate_ids=[candidate.candidate_id],
        generated_at=NOW,
    )
    store.write_json(
        VERSIONED_VALIDATION_DECISIONS_PATH,
        VersionedValidationDecisionSet(
            source_run_id=store.run_id,
            decisions=[substituted],
        ).model_dump(mode="json", by_alias=True),
    )
    store.write_json(
        VERSIONED_VALIDATION_FINDINGS_PATH,
        VersionedConfirmedFindingSet(
            source_run_id=store.run_id,
            confirmation_semantics="verified-independent-replay",
            findings=[confirmed_finding],
        ).model_dump(mode="json", by_alias=True),
    )
    store.write_text(VERSIONED_VALIDATION_REPORT_PATH, "# Substituted projection\n")
    store.write_json(
        VERSIONED_VALIDATION_INDEX_PATH,
        index.model_dump(mode="json", by_alias=True),
    )
    store.append_event("test.substituted-projection.created", {})
    store.seal()

    with pytest.raises(ValueError, match="does not exactly supersede"):
        load_validation_snapshot(store.path)
