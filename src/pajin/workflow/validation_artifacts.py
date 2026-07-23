"""Persist and load source and reproduction-backed validation projections."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pajin.domain.models import Finding
from pajin.domain.validation import (
    AtomicClaimType,
    CandidateFinding,
    ClaimReplayAssessment,
    ClaimReplayStatus,
    ConfirmationBasis,
    FindingDisposition,
    FindingValidationSet,
    PublicFindingState,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
    ValidatorOutputArtifact,
    VersionedClaimReplaySet,
    VersionedConfirmedFindingSet,
    VersionedValidationDecisionSet,
    VersionedValidationIndex,
    candidate_atomic_claims,
)
from pajin.runtime.store import (
    RunIntegritySeal,
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json

VERSIONED_VALIDATION_ROOT = "validation/v1alpha1"
VERSIONED_VALIDATION_INDEX_PATH = f"{VERSIONED_VALIDATION_ROOT}/index.json"
VERSIONED_VALIDATION_DECISIONS_PATH = f"{VERSIONED_VALIDATION_ROOT}/decisions.json"
VERSIONED_VALIDATION_FINDINGS_PATH = f"{VERSIONED_VALIDATION_ROOT}/findings.json"
VERSIONED_VALIDATION_CLAIM_REPLAYS_PATH = f"{VERSIONED_VALIDATION_ROOT}/claim-replays.json"
VERSIONED_VALIDATION_REPORT_PATH = f"{VERSIONED_VALIDATION_ROOT}/report.md"
VALIDATOR_OUTPUT_PATH = "validator-output.json"
_MAX_VALIDATION_ARTIFACT_BYTES = 64 * 1024 * 1024
_SOURCE_VALIDATION_PATHS = (
    "candidate-findings.json",
    "validation-decisions.json",
    "findings.json",
)
_VERSIONED_VALIDATION_PATHS = (
    VERSIONED_VALIDATION_INDEX_PATH,
    VERSIONED_VALIDATION_DECISIONS_PATH,
    VERSIONED_VALIDATION_FINDINGS_PATH,
    VERSIONED_VALIDATION_REPORT_PATH,
)


class ValidationSnapshotSemantics(StrEnum):
    LEGACY_UNVERSIONED = "legacy-unversioned"
    VERIFIED_REPLAY_EVIDENCE = "verified-replay-evidence"
    VERIFIED_INDEPENDENT_REPLAY = "verified-independent-replay"


@dataclass(frozen=True, slots=True)
class LoadedValidationSnapshot:
    validation: FindingValidationSet
    semantics: ValidationSnapshotSemantics
    index: VersionedValidationIndex | None = None
    claim_replays: VersionedClaimReplaySet | None = None

    @property
    def product_confirmed_findings(self) -> list[Finding]:
        if self.semantics is ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY:
            return self.validation.confirmed_findings
        return []

    @property
    def public_states(self) -> dict[PublicFindingState, list[str]]:
        if self.index is not None and self.index.public_states is not None:
            return self.index.public_states
        return {
            state: [
                decision.candidate_id
                for decision in self.validation.decisions
                if decision.disposition.value == state.value
            ]
            for state in PublicFindingState
        }


def write_validation_artifacts(
    store: RunStore,
    validation: FindingValidationSet,
    *,
    validator_output: ValidatorOutputArtifact | None = None,
) -> None:
    """Write the immutable pre-replay source snapshot used by legacy consumers."""

    store.write_json(
        "candidate-findings.json",
        [candidate.model_dump(mode="json") for candidate in validation.candidates],
    )
    store.write_json(
        "validation-decisions.json",
        [decision.model_dump(mode="json") for decision in validation.decisions],
    )
    candidates_by_disposition = _candidates_by_disposition(validation.decisions)
    store.write_json(
        "validation-index.json",
        {
            "candidatesByDisposition": candidates_by_disposition,
            "confirmedFindingIds": [
                finding.finding_id for finding in validation.confirmed_findings
            ],
        },
    )
    if validator_output is not None:
        if validator_output.source_run_id != store.run_id:
            raise ValueError("Validator output belongs to another source Run")
        store.write_json(
            VALIDATOR_OUTPUT_PATH,
            validator_output.model_dump(mode="json", by_alias=True),
        )


def load_source_validation_artifacts(
    run_path: Path,
    *,
    verified_snapshot: VerifiedRunSnapshot | None = None,
    expected_run_id: str | None = None,
    expected_root_digest: str | None = None,
) -> FindingValidationSet:
    """Reload the sealed, pre-replay source snapshot without reinterpreting it."""

    root = run_path.resolve()
    authority = _validation_authority(
        root,
        verified_snapshot=verified_snapshot,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
    )
    snapshot = load_verified_run_artifacts(
        root,
        requests={path: _MAX_VALIDATION_ARTIFACT_BYTES for path in _SOURCE_VALIDATION_PATHS},
        expected_run_id=authority.verification.run_id if authority is not None else None,
    )
    if authority is not None:
        require_same_authority(
            authority,
            snapshot,
            message="sealed validation Run changed while artifacts were loaded",
        )
    return load_source_validation_artifacts_from_snapshot(snapshot)


def load_source_validation_artifacts_from_snapshot(
    snapshot: VerifiedRunSnapshot,
) -> FindingValidationSet:
    """Interpret source validation artifacts already pinned to one verified snapshot."""

    candidates = [
        CandidateFinding.model_validate(item)
        for item in _read_json_list(snapshot, "candidate-findings.json")
    ]
    decisions = [
        ValidationDecision.model_validate(item)
        for item in _read_json_list(snapshot, "validation-decisions.json")
    ]
    findings = [Finding.model_validate(item) for item in _read_json_list(snapshot, "findings.json")]
    return FindingValidationSet(
        candidates=candidates,
        decisions=decisions,
        confirmed_findings=findings,
    )


def load_validation_snapshot(
    run_path: Path,
    *,
    verified_snapshot: VerifiedRunSnapshot | None = None,
    expected_run_id: str | None = None,
    expected_root_digest: str | None = None,
) -> LoadedValidationSnapshot:
    """Load the newest supported projection, failing closed if versioned data is invalid."""

    root = run_path.resolve()
    initial = _validation_authority(
        root,
        verified_snapshot=verified_snapshot,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
    ) or load_verified_run_snapshot(root)
    sealed_paths = {artifact.path for seal in initial.seals for artifact in seal.artifacts}
    if VERSIONED_VALIDATION_INDEX_PATH not in sealed_paths:
        if any(path.startswith(f"{VERSIONED_VALIDATION_ROOT}/") for path in sealed_paths):
            raise ValueError("versioned validation artifacts exist without their index")
        source_snapshot = load_verified_run_artifacts(
            root,
            requests={path: _MAX_VALIDATION_ARTIFACT_BYTES for path in _SOURCE_VALIDATION_PATHS},
            expected_run_id=initial.verification.run_id,
        )
        require_same_authority(
            initial,
            source_snapshot,
            message="sealed validation Run changed while artifacts were loaded",
        )
        return LoadedValidationSnapshot(
            validation=load_source_validation_artifacts_from_snapshot(source_snapshot),
            semantics=ValidationSnapshotSemantics.LEGACY_UNVERSIONED,
        )

    preliminary_requests = {
        path: _MAX_VALIDATION_ARTIFACT_BYTES
        for path in (*_SOURCE_VALIDATION_PATHS, *_VERSIONED_VALIDATION_PATHS)
    }
    preliminary = load_verified_run_artifacts(
        root,
        requests=preliminary_requests,
        expected_run_id=initial.verification.run_id,
    )
    require_same_authority(
        initial,
        preliminary,
        message="sealed validation Run changed while artifacts were loaded",
    )
    index = VersionedValidationIndex.model_validate(
        strict_json(
            preliminary,
            VERSIONED_VALIDATION_INDEX_PATH,
            label="versioned validation index",
            max_bytes=_MAX_VALIDATION_ARTIFACT_BYTES,
            missing_or_invalid_message="versioned validation index could not be loaded",
        )
    )
    final_requests = dict(preliminary_requests)
    final_requests[index.candidate_findings_path] = _MAX_VALIDATION_ARTIFACT_BYTES
    if index.claim_replays_path is not None:
        final_requests[index.claim_replays_path] = _MAX_VALIDATION_ARTIFACT_BYTES
    snapshot = load_verified_run_artifacts(
        root,
        requests=final_requests,
        expected_run_id=initial.verification.run_id,
    )
    require_same_authority(
        preliminary,
        snapshot,
        message="sealed validation Run changed while artifacts were loaded",
    )
    index, validation, claim_replays, source_run_ids = _load_versioned_projection(snapshot)
    _validate_projection_run_identity(source_run_ids, snapshot.verification.run_id)
    source_validation = load_source_validation_artifacts_from_snapshot(snapshot)
    _validate_projection_content(index, validation, claim_replays, source_validation)
    _validate_projection_seal_binding(index, list(snapshot.seals))
    _validate_projection_lineage(index, validation, claim_replays)

    return LoadedValidationSnapshot(
        validation=validation,
        semantics=ValidationSnapshotSemantics(index.confirmation_semantics),
        index=index,
        claim_replays=claim_replays,
    )


def _validation_authority(
    root: Path,
    *,
    verified_snapshot: VerifiedRunSnapshot | None,
    expected_run_id: str | None,
    expected_root_digest: str | None,
) -> VerifiedRunSnapshot | None:
    if verified_snapshot is not None:
        if expected_run_id is not None or expected_root_digest is not None:
            raise ValueError(
                "verified validation snapshot cannot be combined with expected Run identity"
            )
        if verified_snapshot.run_path.resolve() != root:
            raise ValueError("verified validation snapshot belongs to another Run path")
        return verified_snapshot
    if (expected_run_id is None) != (expected_root_digest is None):
        raise ValueError("expected validation Run ID and root digest must be provided together")
    if expected_run_id is None:
        return None
    snapshot = load_verified_run_snapshot(root, expected_run_id=expected_run_id)
    if snapshot.verification.root_digest != expected_root_digest:
        raise ValueError("sealed validation Run root digest differs from the expected Run")
    return snapshot


def _load_versioned_projection(
    snapshot: VerifiedRunSnapshot,
) -> tuple[
    VersionedValidationIndex,
    FindingValidationSet,
    VersionedClaimReplaySet | None,
    tuple[str, ...],
]:
    try:
        index = VersionedValidationIndex.model_validate(
            strict_json(
                snapshot,
                VERSIONED_VALIDATION_INDEX_PATH,
                label="versioned validation index",
                max_bytes=_MAX_VALIDATION_ARTIFACT_BYTES,
                missing_or_invalid_message="versioned validation index could not be loaded",
            )
        )
        decision_set = VersionedValidationDecisionSet.model_validate(
            strict_json(
                snapshot,
                VERSIONED_VALIDATION_DECISIONS_PATH,
                label="versioned validation decisions",
                max_bytes=_MAX_VALIDATION_ARTIFACT_BYTES,
                missing_or_invalid_message="versioned validation decisions could not be loaded",
            )
        )
        finding_set = VersionedConfirmedFindingSet.model_validate(
            strict_json(
                snapshot,
                VERSIONED_VALIDATION_FINDINGS_PATH,
                label="versioned confirmed findings",
                max_bytes=_MAX_VALIDATION_ARTIFACT_BYTES,
                missing_or_invalid_message="versioned confirmed findings could not be loaded",
            )
        )
        candidates = [
            CandidateFinding.model_validate(item)
            for item in _read_json_list(snapshot, index.candidate_findings_path)
        ]
        claim_replays = (
            VersionedClaimReplaySet.model_validate(
                strict_json(
                    snapshot,
                    index.claim_replays_path,
                    label="versioned Claim replay assessments",
                    max_bytes=_MAX_VALIDATION_ARTIFACT_BYTES,
                    missing_or_invalid_message=(
                        "versioned Claim replay assessments could not be loaded"
                    ),
                )
            )
            if index.claim_replays_path is not None
            else None
        )
    except ValueError as exc:
        raise ValueError("versioned validation projection could not be loaded") from exc
    if index.confirmation_semantics != finding_set.confirmation_semantics:
        raise ValueError("versioned validation projection semantics differ across artifacts")

    return (
        index,
        FindingValidationSet(
            candidates=candidates,
            decisions=decision_set.decisions,
            confirmed_findings=finding_set.findings,
        ),
        claim_replays,
        (
            index.source_run_id,
            decision_set.source_run_id,
            finding_set.source_run_id,
            *([claim_replays.source_run_id] if claim_replays is not None else []),
        ),
    )


def _validate_projection_run_identity(
    source_run_ids: tuple[str, ...],
    verified_run_id: str,
) -> None:
    if any(source_run_id != verified_run_id for source_run_id in source_run_ids):
        raise ValueError("versioned validation projection belongs to another source Run")


def _validate_projection_content(
    index: VersionedValidationIndex,
    validation: FindingValidationSet,
    claim_replays: VersionedClaimReplaySet | None,
    source_validation: FindingValidationSet,
) -> None:
    if validation.candidates != source_validation.candidates:
        raise ValueError("versioned validation Candidates differ from the sealed source snapshot")
    _validate_source_supersession(validation, source_validation)
    expected_dispositions = _candidates_by_disposition(validation.decisions)
    serialized_dispositions = {
        disposition: expected_dispositions[disposition.value] for disposition in FindingDisposition
    }
    if index.dispositions != serialized_dispositions:
        raise ValueError("versioned validation index differs from its Decision set")
    confirmed_candidate_ids = [
        decision.candidate_id
        for decision in validation.decisions
        if decision.disposition is FindingDisposition.CONFIRMED
    ]
    if index.confirmed_candidate_ids != confirmed_candidate_ids:
        raise ValueError("versioned validation index confirmed Candidates differ")
    if index.confirmation_semantics == "verified-replay-evidence" and (
        confirmed_candidate_ids or validation.confirmed_findings
    ):
        raise ValueError("replay-evidence projection cannot contain product Confirmed findings")
    if any(
        decision.confirmation_basis is not ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY
        for decision in validation.decisions
        if decision.disposition is FindingDisposition.CONFIRMED
    ):
        raise ValueError("versioned confirmed Decisions require verified replay semantics")
    _validate_claim_replay_projection(index, validation, claim_replays)


def _validate_claim_replay_projection(
    index: VersionedValidationIndex,
    validation: FindingValidationSet,
    claim_replays: VersionedClaimReplaySet | None,
) -> None:
    if index.claim_replays_path is None:
        if claim_replays is not None or index.public_states is not None:
            raise ValueError("legacy projection cannot contain Claim replay public state")
        return
    if (
        index.claim_replays_path != VERSIONED_VALIDATION_CLAIM_REPLAYS_PATH
        or claim_replays is None
        or index.public_states is None
    ):
        raise ValueError("Claim replay projection is incomplete")

    candidates_by_id = {candidate.candidate_id: candidate for candidate in validation.candidates}
    decisions_by_id = {decision.candidate_id: decision for decision in validation.decisions}
    assessments_by_candidate: dict[str, list[ClaimReplayAssessment]] = {}
    for assessment in claim_replays.assessments:
        assessments_by_candidate.setdefault(assessment.candidate_id, []).append(assessment)
    expected_claim_order = [
        claim.claim_id
        for candidate in validation.candidates
        if decisions_by_id[candidate.candidate_id].replay_lineage
        for claim in candidate_atomic_claims(candidate)
        if any(
            assessment.claim_id == claim.claim_id
            for assessment in assessments_by_candidate.get(candidate.candidate_id, [])
        )
    ]
    if [item.claim_id for item in claim_replays.assessments] != expected_claim_order:
        raise ValueError("Claim replay assessments must follow Candidate and Claim order")

    for assessment in claim_replays.assessments:
        _validate_claim_replay_assessment(
            assessment,
            candidates_by_id=candidates_by_id,
            decisions_by_id=decisions_by_id,
        )

    for candidate_id, assessments in assessments_by_candidate.items():
        decision = decisions_by_id[candidate_id]
        if decision.replay_lineage and not any(
            assessment.claim_type is AtomicClaimType.VALIDITY
            for assessment in assessments
        ):
            raise ValueError("replayed Candidate is missing its validity Claim assessment")

    expected_public_states = {
        state: [
            decision.candidate_id
            for decision in validation.decisions
            if _loaded_public_state(
                decision,
                assessments_by_candidate.get(decision.candidate_id, []),
            )
            is state
        ]
        for state in PublicFindingState
    }
    if index.public_states != expected_public_states:
        raise ValueError("public validation states differ from Claim replay assessments")


def _validate_claim_replay_assessment(
    assessment: ClaimReplayAssessment,
    *,
    candidates_by_id: dict[str, CandidateFinding],
    decisions_by_id: dict[str, ValidationDecision],
) -> None:
    try:
        candidate = candidates_by_id[assessment.candidate_id]
        decision = decisions_by_id[assessment.candidate_id]
    except KeyError as exc:
        raise ValueError("Claim replay assessment references an unknown Candidate") from exc
    claim = next(
        (
            claim
            for claim in candidate_atomic_claims(candidate)
            if claim.claim_id == assessment.claim_id
        ),
        None,
    )
    if (
        claim is None
        or assessment.candidate_claim_digest != claim.candidate_claim_digest
        or assessment.claim_digest != claim.claim_digest
        or assessment.claim_type is not claim.claim_type
    ):
        raise ValueError("Claim replay assessment differs from its exact Atomic Claim")
    if assessment.assessed_at != decision.decided_at:
        raise ValueError("Claim replay assessment time differs from its Candidate Decision")
    if assessment.claim_type is not AtomicClaimType.VALIDITY:
        if assessment.independent_execution_attested:
            raise ValueError(
                "impact and severity Claim replay cannot attest product confirmation"
            )
        return
    if len(decision.replay_lineage) != 1:
        raise ValueError("validity Claim replay requires exactly one Decision lineage")
    lineage = decision.replay_lineage[0]
    if (
        assessment.replay_run_id != lineage.replay_run_id
        or assessment.replay_outcome_id != lineage.replay_outcome_id
        or assessment.oracle_result_id != lineage.oracle_result_id
        or assessment.replay_request_ids != lineage.replay_request_ids
        or assessment.replay_evidence != lineage.replay_evidence
    ):
        raise ValueError("validity Claim replay differs from Decision replay lineage")
    attested = (
        decision.confirmation_basis is ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY
    )
    if assessment.independent_execution_attested is not attested:
        raise ValueError("validity Claim attestation differs from its Decision")
    _validate_claim_replay_status_against_decision(assessment, decision)


def _validate_claim_replay_status_against_decision(
    assessment: ClaimReplayAssessment,
    decision: ValidationDecision,
) -> None:
    reason = decision.reason_codes[0]
    objective_reasons = {
        ValidationReasonCode.TARGET_UNDECLARED,
        ValidationReasonCode.TARGET_OUT_OF_SCOPE,
        ValidationReasonCode.THREAT_CLASS_UNDECLARED,
        ValidationReasonCode.EVIDENCE_MISSING,
        ValidationReasonCode.EVIDENCE_UNLINKED,
        ValidationReasonCode.EVIDENCE_FILE_MISSING,
        ValidationReasonCode.SOURCE_REQUEST_MISMATCH,
    }
    if (
        reason in objective_reasons
        or reason is ValidationReasonCode.CANDIDATE_PRODUCER_NOT_ADMITTED
    ):
        expected = ClaimReplayStatus.NOT_ELIGIBLE
    elif reason is ValidationReasonCode.REPLAY_ORACLE_CONTRADICTED:
        expected = ClaimReplayStatus.NOT_REPRODUCED
    elif reason is ValidationReasonCode.REPLAY_ORACLE_INCONCLUSIVE or reason in {
        ValidationReasonCode.EXECUTION_FAILED,
        ValidationReasonCode.REPLAY_EXECUTION_FAILED,
        ValidationReasonCode.REPLAY_CANCELLED,
        ValidationReasonCode.REPLAY_TIMED_OUT,
        ValidationReasonCode.REPLAY_TARGET_UNAVAILABLE,
    }:
        expected = ClaimReplayStatus.INCONCLUSIVE
    elif reason is ValidationReasonCode.REPLAY_NOT_ELIGIBLE:
        expected = ClaimReplayStatus.NOT_ELIGIBLE
    elif reason in {
        ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED,
        ValidationReasonCode.INDEPENDENT_EXECUTION_ATTESTATION_MISSING,
        ValidationReasonCode.VALIDATOR_DISAGREED,
        ValidationReasonCode.VALIDATOR_OMITTED,
        ValidationReasonCode.VALIDATOR_UNAVAILABLE,
        ValidationReasonCode.VALIDATOR_CANCELLED,
    }:
        expected = ClaimReplayStatus.REPRODUCED
    else:
        return
    if assessment.status is not expected:
        raise ValueError("Claim replay status differs from its Gate reason")


def _loaded_public_state(
    decision: ValidationDecision,
    assessments: list[ClaimReplayAssessment],
) -> PublicFindingState:
    if decision.disposition is FindingDisposition.CONFIRMED:
        return PublicFindingState.CONFIRMED
    if not assessments:
        return PublicFindingState(decision.disposition.value)
    reason = decision.reason_codes[0]
    if reason is ValidationReasonCode.REPLAY_ORACLE_CONTRADICTED:
        return PublicFindingState.NOT_REPRODUCED
    if any(
        assessment.status is ClaimReplayStatus.REPRODUCED
        for assessment in assessments
    ):
        return PublicFindingState.PARTIALLY_CONFIRMED
    if any(
        assessment.status is ClaimReplayStatus.NOT_REPRODUCED
        for assessment in assessments
    ):
        return PublicFindingState.NOT_REPRODUCED
    if any(
        assessment.status is ClaimReplayStatus.INCONCLUSIVE
        for assessment in assessments
    ):
        return PublicFindingState.INCONCLUSIVE
    return PublicFindingState(decision.disposition.value)


def _validate_projection_seal_binding(
    index: VersionedValidationIndex,
    seals: list[RunIntegritySeal],
) -> None:
    source_seal_index = next(
        (
            position
            for position, seal in enumerate(seals)
            if seal.root_digest == index.candidate_source_root_digest
        ),
        None,
    )
    if source_seal_index is None:
        raise ValueError("versioned projection source seal is not in the Run seal chain")
    source_paths = {
        artifact.path for seal in seals[: source_seal_index + 1] for artifact in seal.artifacts
    }
    if (
        not {
            "candidate-findings.json",
            "validation-decisions.json",
            "findings.json",
        }
        <= source_paths
    ):
        raise ValueError("versioned projection source seal predates validation source artifacts")
    projection_paths = {
        VERSIONED_VALIDATION_INDEX_PATH,
        VERSIONED_VALIDATION_DECISIONS_PATH,
        VERSIONED_VALIDATION_FINDINGS_PATH,
        VERSIONED_VALIDATION_REPORT_PATH,
    }
    if index.claim_replays_path is not None:
        projection_paths.add(index.claim_replays_path)
    sealed_projection_paths = {
        artifact.path
        for seal in seals
        for artifact in seal.artifacts
        if artifact.path in projection_paths
    }
    if sealed_projection_paths != projection_paths:
        raise ValueError("versioned validation projection is not completely sealed")
    if not any(
        projection_paths <= {artifact.path for artifact in seal.artifacts}
        for seal in seals[source_seal_index + 1 :]
    ):
        raise ValueError("versioned validation projection must be bound by one seal")
    if any(
        artifact.path in projection_paths
        for seal in seals[: source_seal_index + 1]
        for artifact in seal.artifacts
    ):
        raise ValueError("versioned projection does not follow its Candidate source seal")


def _validate_projection_lineage(
    index: VersionedValidationIndex,
    validation: FindingValidationSet,
    claim_replays: VersionedClaimReplaySet | None,
) -> None:
    replay_run_ids: list[str] = []
    replay_outcome_ids: list[str] = []
    for decision in validation.decisions:
        for lineage in decision.replay_lineage:
            if lineage.candidate_source_root_digest != index.candidate_source_root_digest:
                raise ValueError("Decision replay lineage differs from the indexed source seal")
            replay_run_ids.append(lineage.replay_run_id)
            replay_outcome_ids.append(lineage.replay_outcome_id)
    if not replay_run_ids:
        raise ValueError("versioned validation projection has no verified replay lineage")
    if len(replay_run_ids) != len(set(replay_run_ids)):
        raise ValueError("versioned validation projection reuses a replay Run")
    if len(replay_outcome_ids) != len(set(replay_outcome_ids)):
        raise ValueError("versioned validation projection reuses a ReplayOutcome")
    if claim_replays is not None:
        validity_assessments = [
            item
            for item in claim_replays.assessments
            if item.claim_type is AtomicClaimType.VALIDITY
        ]
        if [item.replay_run_id for item in validity_assessments] != replay_run_ids:
            raise ValueError("validity Claim replay lineage differs from validation Decisions")
        if [item.replay_outcome_id for item in validity_assessments] != replay_outcome_ids:
            raise ValueError("validity Claim ReplayOutcome differs from validation Decisions")


def _validate_source_supersession(
    validation: FindingValidationSet,
    source_validation: FindingValidationSet,
) -> None:
    if source_validation.confirmed_findings or any(
        decision.disposition is FindingDisposition.CONFIRMED
        or decision.confirmation_basis is not None
        or decision.replay_request_ids
        or decision.replay_outcome_ids
        or decision.replay_lineage
        for decision in source_validation.decisions
    ):
        raise ValueError("versioned projection requires an unreproduced source snapshot")
    source_decisions = {decision.candidate_id: decision for decision in source_validation.decisions}
    for decision in validation.decisions:
        source_decision = source_decisions[decision.candidate_id]
        if not decision.replay_lineage:
            if decision != source_decision:
                raise ValueError("unreplayed Decision differs from the sealed source snapshot")
            continue
        if (
            decision.method is not ValidationMethod.RESTRICTED_REPLAY_GATE
            or decision.validator_id != "trusted-core:confirmed-gate"
            or decision.supersedes_decision_id != source_decision.decision_id
            or decision.supporting_evidence != source_decision.supporting_evidence
            or decision.contradicting_evidence != source_decision.contradicting_evidence
        ):
            raise ValueError("replay Decision does not exactly supersede its source Decision")
        if decision.decided_at < source_decision.decided_at or any(
            decision.decided_at < lineage.verified_at for lineage in decision.replay_lineage
        ):
            raise ValueError("replay Decision predates its source Decision or receipt verification")


def _candidates_by_disposition(
    decisions: list[ValidationDecision],
) -> dict[str, list[str]]:
    return {
        disposition.value: [
            decision.candidate_id for decision in decisions if decision.disposition is disposition
        ]
        for disposition in FindingDisposition
    }


def _read_json_list(snapshot: VerifiedRunSnapshot, relative_path: str) -> list[object]:
    name = Path(relative_path).name
    return strict_json(
        snapshot,
        relative_path,
        label=f"validation artifact {name}",
        max_bytes=_MAX_VALIDATION_ARTIFACT_BYTES,
        expected_type=list,
        missing_or_invalid_message=f"validation artifact {name} could not be loaded",
        type_message=f"validation artifact must contain a list: {name}",
    )
