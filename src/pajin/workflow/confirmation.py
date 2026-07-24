"""Public facade for replay confirmation policy and durable projection writes.

The stable import surface remains here.  Pure reason-matrix evaluation lives in
``confirmation_policy`` and all OS locking/atomic recovery lives in
``confirmation_projection``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path

from pajin.domain.models import AgentPlan, CampaignManifest
from pajin.domain.replay import ReplayArtifactSet
from pajin.domain.validation import (
    CandidateFinding,
    FindingValidationSet,
    ReplayConfirmationLineage,
    ValidationDecision,
)
from pajin.replay.runtime import VerifiedReplayResult
from pajin.replay.tickets import ReplayTicketFinalizationVerifier
from pajin.workflow import confirmation_policy as _policy
from pajin.workflow.confirmation_policy import (
    _ConfirmationProjection,
    _independently_attested_successful_replay_disposition,
    _render_confirmation_report,
    _ReplayDisposition,
    _semantic_supported,
    _successful_replay_disposition,
)
from pajin.workflow.confirmation_projection import (
    _fsync_file as _projection_fsync_file,
)
from pajin.workflow.confirmation_projection import (
    apply_confirmed_gate as _apply_confirmed_gate,
)
from pajin.workflow.validation_artifacts import LoadedValidationSnapshot

__all__ = [
    "_ConfirmationProjection",
    "_ReplayDisposition",
    "_build_confirmation_projection",
    "_fsync_file",
    "_render_confirmation_report",
    "_semantic_supported",
    "_successful_replay_disposition",
    "apply_confirmed_gate",
    "decide_replay_confirmation",
]


def apply_confirmed_gate(
    *,
    source_run_path: Path,
    replay_run_paths: Sequence[Path],
    tickets: ReplayTicketFinalizationVerifier,
    decided_at: datetime | None = None,
    additional_artifacts: Mapping[str, bytes] | None = None,
) -> LoadedValidationSnapshot:
    """Apply or recover one cross-process serialized confirmation projection."""

    return _apply_confirmed_gate(
        source_run_path=source_run_path,
        replay_run_paths=replay_run_paths,
        tickets=tickets,
        build_projection=_build_confirmation_projection,
        fsync_file=_fsync_file,
        decided_at=decided_at,
        additional_artifacts=additional_artifacts,
    )


def decide_replay_confirmation(
    *,
    candidate: CandidateFinding,
    source_decision: ValidationDecision,
    artifact_set: ReplayArtifactSet,
    lineage: ReplayConfirmationLineage,
    decided_at: datetime,
    independent_execution_attested: bool = False,
) -> ValidationDecision:
    """Pure reason-matrix evaluation over an already verified replay artifact set."""

    return _policy._decide_replay_confirmation(
        candidate=candidate,
        source_decision=source_decision,
        artifact_set=artifact_set,
        lineage=lineage,
        decided_at=decided_at,
        allow_legacy_confirmation_contradiction=False,
        successful_replay_disposition=(
            _independently_attested_successful_replay_disposition
            if independent_execution_attested
            else _successful_replay_disposition
        ),
    )


def _build_confirmation_projection(
    *,
    root: Path,
    source_run_id: str,
    source_validation: FindingValidationSet,
    campaign: CampaignManifest,
    plan: AgentPlan,
    verified_results: list[VerifiedReplayResult],
    evaluated_at: datetime,
) -> _ConfirmationProjection:
    """Compatibility seam that injects the facade's disposition authority."""

    return _policy._build_confirmation_projection(
        root=root,
        source_run_id=source_run_id,
        source_validation=source_validation,
        campaign=campaign,
        plan=plan,
        verified_results=verified_results,
        evaluated_at=evaluated_at,
        successful_replay_disposition=_successful_replay_disposition,
    )


def _fsync_file(path: Path) -> None:
    """Compatibility seam for durable-write failure injection."""

    _projection_fsync_file(path)
