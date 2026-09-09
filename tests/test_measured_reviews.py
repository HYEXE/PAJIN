"""Review state and storage checks; model-only retest fixtures are not execution proof."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import DatabaseError

from pajin.control_plane.database import (
    CURRENT_SCHEMA_VERSION,
    MEASURED_REVIEW_SCHEMA_VERSION,
    V14_CONTROL_PLANE_TABLES,
    ControlPlaneRepository,
    MeasuredReviewRevisionRecord,
    SchemaVersionRecord,
)
from pajin.control_plane.measured_reviews.models import (
    AssessReview,
    AttachRetest,
    DecideReview,
    HumanAssessment,
    OpenReview,
    ReviewCommand,
    ReviewEvidence,
    ReviewRevision,
    review_digest,
)
from pajin.control_plane.measured_reviews.state import rebuild_review
from pajin.control_plane.models import SubmitRunRequest
from pajin.control_plane.security import CheckpointSigner
from pajin.control_plane.service import ControlPlaneService
from pajin.workflow.ai_measured_product_flow import AIMeasuredProduct
from tests.test_ai_measured_product import _ProductContext

pytest_plugins = ("tests.test_ai_measured_product",)

NOW = datetime(2026, 9, 7, tzinfo=UTC)


@pytest.fixture(scope="module")
def review_evidence(ai_product_context: _ProductContext) -> ReviewEvidence:
    return ReviewEvidence.model_validate(
        {"domain": "ai", "projection": ai_product_context.outcome.product, "verifiedAt": NOW}
    )


def _assessment(evidence: ReviewEvidence) -> HumanAssessment:
    return HumanAssessment.model_validate(
        {
            "impact": "The controlled target exposes its synthetic private system note.",
            "severity": "medium",
            "severityRationale": "Human assessment of the isolated benchmark only.",
            "evidenceDigest": evidence.evidence_digest,
            "limitations": "Production impact and raw transcript were not assessed.",
            "remediation": [
                {
                    "action": "Separate confidential data from the response path.",
                    "verification": "Run the approved disclosure check after the change.",
                }
            ],
            "retestPlan": "Compare separately verified evidence and review any remaining exposure.",
        }
    )


def _revision(
    command: ReviewCommand,
    *,
    previous: ReviewRevision | None = None,
    actor: str = "writer",
) -> ReviewRevision:
    sequence = 1 if previous is None else previous.revision + 1
    return ReviewRevision.model_validate(
        {
            "reviewId": "review_" + "a" * 32,
            "revision": sequence,
            "previousDigest": None if previous is None else previous.record_digest,
            "actor": actor,
            "actorRole": "approver" if isinstance(command, DecideReview) else "operator",
            "recordedAt": NOW + timedelta(minutes=sequence),
            "requestKey": f"request-{sequence}",
            "requestDigest": review_digest("unit-request", command.model_dump(mode="json")),
            "command": command,
        }
    )


def _accepted(evidence: ReviewEvidence) -> list[ReviewRevision]:
    opened = _revision(OpenReview(title="Disclosure review", evidence=evidence))
    assessed = _revision(AssessReview(assessment=_assessment(evidence)), previous=opened)
    accepted = _revision(
        DecideReview(decision="accept", reason="The bounded assessment and plan are supported."),
        previous=assessed,
        actor="reviewer",
    )
    return [opened, assessed, accepted]


def _model_only_retest(evidence: ReviewEvidence, *, replace_source: bool = True) -> ReviewEvidence:
    """Exercise transition rules without pretending this fixture has a retained source."""
    material = evidence.projection.model_dump(mode="json", by_alias=True)
    material.pop("productId")
    material.pop("productDigest")
    if replace_source:
        reference = {
            "evaluationId": "ai-replay-floor-evaluation_" + "e" * 64,
            "evaluationDigest": "e" * 64,
        }
        material["sourceEvaluation"] = reference
        material["floor"]["evaluation"] = reference
    else:
        for observation in material["floor"]["observations"]:
            if observation["metric"]["metricId"] == "common.time-to-first-valid-result":
                observation["numerator"] += 1
    return ReviewEvidence.model_validate(
        {
            "domain": "ai",
            "projection": AIMeasuredProduct.model_validate_json(json.dumps(material)),
            "verifiedAt": NOW + timedelta(minutes=3, seconds=10),
        }
    )


def test_review_requires_distinct_human_and_reacceptance_after_retest(
    review_evidence: ReviewEvidence,
) -> None:
    history = _accepted(review_evidence)
    accepted = rebuild_review(history)
    assert accepted.state == "accepted"
    assert accepted.assessment_author == "writer"
    assert accepted.reviewer == "reviewer"
    retest = _revision(
        AttachRetest(
            evidence=_model_only_retest(review_evidence),
            changeReference="change-42",
            conclusion="inconclusive",
            rationale="The new benchmark evidence needs human interpretation.",
        ),
        previous=history[-1],
    )
    pending = rebuild_review([*history, retest])
    assert pending.state == "awaiting-review"
    assert pending.reviewer is None
    assert pending.retest is not None
    assert not pending.retest.execution_after_remediation_verified
    decided = _revision(
        DecideReview(decision="accept", reason="The report correctly retains the uncertainty."),
        previous=retest,
        actor="reviewer",
    )
    reviewed = rebuild_review([*history, retest, decided])
    assert reviewed.state == "accepted"
    assert reviewed.revision == 5
    assert reviewed.generic_finding_confirmed is False
    assert reviewed.sarif_authorized is False
    assert reviewed.execution_authorized is False
    assert reviewed.evidence.projection == review_evidence.projection


def test_assessment_change_invalidates_previous_acceptance(review_evidence: ReviewEvidence) -> None:
    history = _accepted(review_evidence)
    changed = _assessment(review_evidence).model_copy(
        update={"impact": "A revised impact statement"}
    )
    revision = _revision(AssessReview(assessment=changed), previous=history[-1])
    state = rebuild_review([*history, revision])
    assert state.state == "awaiting-review"
    assert state.reviewer is state.decision is None
    assert len(state.history) == 4


def test_self_review_and_missing_assessment_are_rejected(review_evidence: ReviewEvidence) -> None:
    history = _accepted(review_evidence)
    own = _revision(
        DecideReview(decision="accept", reason="self review"), previous=history[1], actor="writer"
    )
    with pytest.raises(ValueError, match="contributors"):
        rebuild_review([*history[:2], own])
    premature = _revision(
        DecideReview(decision="accept", reason="no assessment"),
        previous=history[0],
        actor="reviewer",
    )
    with pytest.raises(ValueError, match="complete assessment"):
        rebuild_review([history[0], premature])


@pytest.mark.parametrize("mutation", ["gap", "digest", "actor", "backward-time"])
def test_changed_history_cannot_be_replayed(review_evidence: ReviewEvidence, mutation: str) -> None:
    history = _accepted(review_evidence)
    if mutation == "gap":
        history.pop(1)
    else:
        change: dict[str, object] = {
            "digest": {"previous_digest": "0" * 64},
            "actor": {"actor": "another-writer"},
            "backward-time": {"recorded_at": NOW - timedelta(days=1)},
        }[mutation]
        history[1] = history[1].model_copy(update=change)
    with pytest.raises(ValueError):
        rebuild_review(history)


@pytest.mark.parametrize("replace_source", [True, False])
def test_retest_cannot_reuse_original_source_or_verification(
    review_evidence: ReviewEvidence, replace_source: bool
) -> None:
    history = _accepted(review_evidence)
    evidence = (
        review_evidence
        if replace_source
        else _model_only_retest(review_evidence, replace_source=False)
    )
    retest = _revision(
        AttachRetest(
            evidence=evidence,
            changeReference="change-42",
            conclusion="reviewer-assessed-resolved",
            rationale="A claim without distinct measurement is rejected.",
        ),
        previous=history[-1],
    )
    with pytest.raises(ValueError, match="retest evidence"):
        rebuild_review([*history, retest])


@pytest.mark.parametrize("marker", [0, 1, "false", True])
def test_review_evidence_does_not_coerce_disclosure_markers(
    review_evidence: ReviewEvidence, marker: object
) -> None:
    material = review_evidence.model_dump()
    material["raw_content_included"] = marker
    with pytest.raises(ValueError):
        ReviewEvidence.model_validate(material)


def test_v14_upgrade_preserves_existing_run_and_installs_history_guards(tmp_path: Path) -> None:
    repository = ControlPlaneRepository(f"sqlite:///{tmp_path / 'reviews.db'}")
    try:
        repository.initialize()
        service = ControlPlaneService(
            repository,
            CheckpointSigner(active_key_id="unit-v1", keys={"unit-v1": b"u" * 32}),
        )
        submitted = service.submit_run(
            SubmitRunRequest(
                campaign_name="review-migration",
                input={"objective": "preserve existing execution state"},
                idempotency_key="existing-run",
            ),
            actor="writer",
        )
        with repository.engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE cp_checkpoint_key_identities")
            connection.exec_driver_sql("DROP TABLE cp_measured_review_revisions")
            connection.execute(
                text("DELETE FROM cp_schema_version WHERE version >= :version"),
                {"version": MEASURED_REVIEW_SCHEMA_VERSION},
            )
            before = connection.exec_driver_sql("SELECT * FROM cp_runs").all()
        assert set(inspect(repository.engine).get_table_names()) == V14_CONTROL_PLANE_TABLES
        repository.initialize()
        with repository.engine.connect() as connection:
            assert connection.exec_driver_sql("SELECT * FROM cp_runs").all() == before
            assert connection.execute(select(SchemaVersionRecord.version)).scalars().all() == list(
                range(1, CURRENT_SCHEMA_VERSION + 1)
            )
            guards = (
                connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                    "AND tbl_name = 'cp_measured_review_revisions'"
                )
                .scalars()
                .all()
            )
        assert set(guards) == {
            "cp_measured_review_revisions_no_update",
            "cp_measured_review_revisions_no_delete",
            "cp_measured_review_revisions_no_replace",
        }
        assert service.get_run(submitted.run.run_id) == submitted.run
        repository.initialize()
    finally:
        repository.close()


@pytest.mark.parametrize("mutation", ["update", "delete", "replace"])
def test_review_history_rows_cannot_be_mutated(
    tmp_path: Path, review_evidence: ReviewEvidence, mutation: str
) -> None:
    revision = _accepted(review_evidence)[0]
    repository = ControlPlaneRepository(f"sqlite:///{tmp_path / 'history.db'}")
    try:
        repository.initialize()
        with repository.transaction() as session:
            session.add(
                MeasuredReviewRevisionRecord(
                    review_id=revision.review_id,
                    revision=1,
                    source_domain="ai",
                    previous_digest=None,
                    actor=revision.actor,
                    actor_role=revision.actor_role,
                    recorded_at=revision.recorded_at,
                    request_key=revision.request_key,
                    request_digest=revision.request_digest,
                    record_digest=revision.record_digest,
                    payload=revision.model_dump(mode="json", by_alias=True),
                )
            )
        statements = {
            "update": "UPDATE cp_measured_review_revisions SET actor = 'changed'",
            "delete": "DELETE FROM cp_measured_review_revisions",
            "replace": "INSERT OR REPLACE INTO cp_measured_review_revisions "
            "SELECT * FROM cp_measured_review_revisions",
        }
        with pytest.raises(DatabaseError), repository.engine.begin() as connection:
            connection.exec_driver_sql(statements[mutation])
        repository.initialize()
        with repository.read_transaction() as session:
            row = session.scalar(select(MeasuredReviewRevisionRecord))
            assert row is not None and row.actor == revision.actor
    finally:
        repository.close()
