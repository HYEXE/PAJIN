"""Persist and load source and reproduction-backed validation projections."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pajin.domain.models import Finding
from pajin.domain.validation import (
    CandidateFinding,
    ConfirmationBasis,
    FindingDisposition,
    FindingValidationSet,
    ValidationDecision,
    ValidationMethod,
    VersionedConfirmedFindingSet,
    VersionedValidationDecisionSet,
    VersionedValidationIndex,
)
from pajin.runtime.store import RunIntegritySeal, RunStore, verify_run_integrity

VERSIONED_VALIDATION_ROOT = "validation/v1alpha1"
VERSIONED_VALIDATION_INDEX_PATH = f"{VERSIONED_VALIDATION_ROOT}/index.json"
VERSIONED_VALIDATION_DECISIONS_PATH = f"{VERSIONED_VALIDATION_ROOT}/decisions.json"
VERSIONED_VALIDATION_FINDINGS_PATH = f"{VERSIONED_VALIDATION_ROOT}/findings.json"
VERSIONED_VALIDATION_REPORT_PATH = f"{VERSIONED_VALIDATION_ROOT}/report.md"


class ValidationSnapshotSemantics(StrEnum):
    LEGACY_UNVERSIONED = "legacy-unversioned"
    VERIFIED_INDEPENDENT_REPLAY = "verified-independent-replay"


@dataclass(frozen=True, slots=True)
class LoadedValidationSnapshot:
    validation: FindingValidationSet
    semantics: ValidationSnapshotSemantics
    index: VersionedValidationIndex | None = None

    @property
    def product_confirmed_findings(self) -> list[Finding]:
        if self.semantics is ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY:
            return self.validation.confirmed_findings
        return []


def write_validation_artifacts(
    store: RunStore,
    validation: FindingValidationSet,
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


def load_source_validation_artifacts(run_path: Path) -> FindingValidationSet:
    """Reload the sealed, pre-replay source snapshot without reinterpreting it."""

    root = run_path.resolve()
    verify_run_integrity(root)
    candidates = [
        CandidateFinding.model_validate(item)
        for item in _read_json_list(root / "candidate-findings.json")
    ]
    decisions = [
        ValidationDecision.model_validate(item)
        for item in _read_json_list(root / "validation-decisions.json")
    ]
    findings = [Finding.model_validate(item) for item in _read_json_list(root / "findings.json")]
    return FindingValidationSet(
        candidates=candidates,
        decisions=decisions,
        confirmed_findings=findings,
    )


def load_validation_snapshot(run_path: Path) -> LoadedValidationSnapshot:
    """Load the newest supported projection, failing closed if versioned data is invalid."""

    root = run_path.resolve()
    verification = verify_run_integrity(root)
    index_path = root / VERSIONED_VALIDATION_INDEX_PATH
    if not index_path.is_file():
        versioned_root = root / VERSIONED_VALIDATION_ROOT
        if versioned_root.exists():
            raise ValueError("versioned validation artifacts exist without their index")
        return LoadedValidationSnapshot(
            validation=load_source_validation_artifacts(root),
            semantics=ValidationSnapshotSemantics.LEGACY_UNVERSIONED,
        )

    try:
        index = VersionedValidationIndex.model_validate_json(index_path.read_bytes())
        decision_set = VersionedValidationDecisionSet.model_validate_json(
            (root / VERSIONED_VALIDATION_DECISIONS_PATH).read_bytes()
        )
        finding_set = VersionedConfirmedFindingSet.model_validate_json(
            (root / VERSIONED_VALIDATION_FINDINGS_PATH).read_bytes()
        )
        candidates = [
            CandidateFinding.model_validate(item)
            for item in _read_json_list(root / index.candidate_findings_path)
        ]
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("versioned validation projection could not be loaded") from exc

    if (
        index.source_run_id != verification.run_id
        or decision_set.source_run_id != verification.run_id
        or finding_set.source_run_id != verification.run_id
    ):
        raise ValueError("versioned validation projection belongs to another source Run")
    if not (root / VERSIONED_VALIDATION_REPORT_PATH).is_file():
        raise ValueError("versioned validation projection report is missing")

    validation = FindingValidationSet(
        candidates=candidates,
        decisions=decision_set.decisions,
        confirmed_findings=finding_set.findings,
    )
    source_validation = load_source_validation_artifacts(root)
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
    if any(
        decision.confirmation_basis is not ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY
        for decision in validation.decisions
        if decision.disposition is FindingDisposition.CONFIRMED
    ):
        raise ValueError("versioned confirmed Decisions require verified replay semantics")

    seals = _read_seals(root)
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

    return LoadedValidationSnapshot(
        validation=validation,
        semantics=ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY,
        index=index,
    )


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


def _read_json_list(path: Path) -> list[object]:
    try:
        payload: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"validation artifact could not be loaded: {path.name}") from exc
    if not isinstance(payload, list):
        raise ValueError(f"validation artifact must contain a list: {path.name}")
    return payload


def _read_seals(root: Path) -> list[RunIntegritySeal]:
    try:
        return [
            RunIntegritySeal.model_validate_json(line)
            for line in (root / "run-integrity.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("Run seal chain could not be loaded") from exc
