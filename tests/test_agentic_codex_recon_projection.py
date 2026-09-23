"""Hosted-recon input stays a bounded, inert derivative of the local projection."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import ValidationError

import pajin.agentic.codex_recon_projection as recon_module
from pajin.agentic.codex_recon_draft import (
    CodexReconDraftError,
    admit_codex_recon_turn,
    parse_codex_recon_draft,
)
from pajin.agentic.codex_recon_projection import (
    CodexReconProjection,
    build_codex_recon_projection,
)
from pajin.agentic.codex_routing import (
    CodexAdvisoryStage,
    code_owned_codex_advisory_routing_plan,
)
from pajin.agentic.codex_usage import CodexAdvisoryUsageError, CodexAdvisoryUsageJournal
from pajin.discovery.canonicalization import discovery_digest
from pajin.web_assessment.analysis_proposal import (
    WebAnalysisEvidenceSignal,
    WebAnalysisModelProjection,
    WebAnalysisProjectionDiagnostic,
    WebAnalysisProjectionPath,
)
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun


def _local_projection() -> WebAnalysisModelProjection:
    return WebAnalysisModelProjection(
        apiVersion="pajin.dev/web-analysis-model-projection/v1alpha1",
        kind="WebAnalysisModelProjection",
        projectionId="",
        projectionDigest="",
        diagnostics=(
            WebAnalysisProjectionDiagnostic(
                diagnosticId="sql-login",
                catalogEntryId="pajin.web-analysis.diagnostic.sql-login.v1",
                allowedHypothesisIds=(
                    "pajin.web-analysis.hypothesis.sql-login-authentication-bypass.v1",
                ),
            ),
            WebAnalysisProjectionDiagnostic(
                diagnosticId="object-access",
                catalogEntryId="pajin.web-analysis.diagnostic.object-access.v1",
                allowedHypothesisIds=(
                    "pajin.web-analysis.hypothesis.cross-account-object-access.v1",
                ),
            ),
            WebAnalysisProjectionDiagnostic(
                diagnosticId="dom-xss",
                catalogEntryId="pajin.web-analysis.diagnostic.dom-xss.v1",
                allowedHypothesisIds=("pajin.web-analysis.hypothesis.client-marker-execution.v1",),
            ),
        ),
        attackPaths=(
            WebAnalysisProjectionPath(
                catalogEntryId="pajin.web-analysis.path.sql-login-object-access.v1",
                issueSequence=("sql-login", "object-access"),
                allowedHypothesisIds=(
                    "pajin.web-analysis.hypothesis.authentication-to-object-access.v1",
                ),
                allowedDispositions=("investigate", "insufficient-evidence"),
            ),
            WebAnalysisProjectionPath(
                catalogEntryId="pajin.web-analysis.path.dom-xss.v1",
                issueSequence=("dom-xss",),
                allowedHypothesisIds=("pajin.web-analysis.hypothesis.client-marker-impact.v1",),
                allowedDispositions=("investigate", "insufficient-evidence"),
            ),
        ),
        evidenceSignals=(
            WebAnalysisEvidenceSignal(
                evidenceRef="wae_" + "a" * 32,
                signalKind="discovered-route-count",
                countBucket="two-to-five",
                supportsCatalogEntries=(
                    "pajin.web-analysis.diagnostic.dom-xss.v1",
                    "pajin.web-analysis.diagnostic.object-access.v1",
                    "pajin.web-analysis.diagnostic.sql-login.v1",
                    "pajin.web-analysis.path.dom-xss.v1",
                    "pajin.web-analysis.path.sql-login-object-access.v1",
                ),
            ),
        ),
        projectionState="opaque-proposal-input-not-authority",
        sourceAnchorsEmbedded=False,
        targetContentEmbedded=False,
        rawEvidenceEmbedded=False,
        instructionAuthorized=False,
        toolAccessAuthorized=False,
        capabilityGranted=False,
        permitGranted=False,
        executionAuthorized=False,
    )


def _hosted_projection(monkeypatch: pytest.MonkeyPatch) -> CodexReconProjection:
    source = cast(VerifiedAuthenticatedDiscoveryRun, object())
    expected_run_id = "run_20260915T020000Z_a1b2c3d4"
    expected_root_digest = "b" * 64

    def strict_reload(
        current: VerifiedAuthenticatedDiscoveryRun,
        *,
        expected_run_id: str,
        expected_root_digest: str,
    ) -> SimpleNamespace:
        assert current is source
        assert expected_run_id == "run_20260915T020000Z_a1b2c3d4"
        assert expected_root_digest == "b" * 64
        return SimpleNamespace(model_projection=_local_projection())

    monkeypatch.setattr(recon_module, "build_web_analysis_snapshot", strict_reload)
    return build_codex_recon_projection(
        source,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
    )


def test_hosted_recon_projection_exports_only_catalog_and_bucketed_signals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = _hosted_projection(monkeypatch)
    wire = projection.model_dump_json(by_alias=True)

    assert projection.api_version == "pajin.dev/codex-recon-projection/v1alpha1"
    assert projection.evidence_signals[0].count_bucket == "two-to-five"
    assert projection.source_anchors_embedded is False
    assert projection.target_content_embedded is False
    assert projection.tool_access_authorized is False
    assert "sourceRunId" not in wire
    assert "sourceRootDigest" not in wire
    assert "http://" not in wire
    assert "run_20260915" not in wire
    assert CodexReconProjection.model_validate(projection.model_dump(mode="json")) == projection


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sourceAnchorsEmbedded", True),
        ("targetContentEmbedded", True),
        ("toolAccessAuthorized", True),
        ("executionAuthorized", True),
        ("findingAuthorized", True),
        ("publicationAuthorized", True),
    ],
)
def test_hosted_recon_projection_cannot_claim_authority(
    monkeypatch: pytest.MonkeyPatch, field: str, value: bool
) -> None:
    raw = _hosted_projection(monkeypatch).model_dump(mode="json")
    raw[field] = value
    raw["projectionDigest"] = discovery_digest(
        "pajin.codex-recon-projection/v1alpha1",
        {key: item for key, item in raw.items() if key != "projectionDigest"},
    )
    with pytest.raises(ValidationError):
        CodexReconProjection.model_validate(raw)


def test_hosted_recon_projection_rejects_extra_target_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _hosted_projection(monkeypatch).model_dump(mode="json")
    raw["targetUrl"] = "http://example.invalid/private"
    with pytest.raises(ValidationError):
        CodexReconProjection.model_validate(raw)


def _draft_wire(projection: CodexReconProjection) -> dict[str, object]:
    ref = projection.evidence_signals[0].evidence_ref
    return {
        "apiVersion": "pajin.dev/codex-recon-draft/v1alpha1",
        "kind": "CodexReconDraft",
        "projectionDigest": projection.projection_digest,
        "prioritizedDiagnostics": [
            {
                "rank": rank,
                "diagnosticId": item.diagnostic_id,
                "catalogEntryId": item.catalog_entry_id,
                "hypothesisId": item.allowed_hypothesis_ids[0],
                "evidenceRefs": [ref],
            }
            for rank, item in enumerate(projection.diagnostics, start=1)
        ],
        "pathAssessments": [
            {
                "catalogEntryId": item.catalog_entry_id,
                "hypothesisId": item.allowed_hypothesis_ids[0],
                "issueSequence": list(item.issue_sequence),
                "disposition": "investigate",
                "evidenceRefs": [ref],
            }
            for item in projection.attack_paths
        ],
        "proposalState": "untrusted-hosted-draft-not-authorized",
        "scopeExpansionAuthorized": False,
        "toolRequestCompiled": False,
        "capabilityGranted": False,
        "permitGranted": False,
        "executionAuthorized": False,
        "graphAdmissionAuthorized": False,
        "findingAuthorized": False,
        "reportDeliveryAuthorized": False,
    }


def test_hosted_recon_draft_admits_only_matching_closed_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = _hosted_projection(monkeypatch)
    draft = parse_codex_recon_draft(
        json.dumps(_draft_wire(projection)).encode(), expected_projection=projection
    )

    assert tuple(item.rank for item in draft.prioritized_diagnostics) == (1, 2, 3)
    assert not draft.execution_authorized
    assert not draft.finding_authorized


@pytest.mark.parametrize("mutation", ["foreign-ref", "target-field", "execution", "wrong-digest"])
def test_hosted_recon_draft_rejects_foreign_or_authority_fields(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    projection = _hosted_projection(monkeypatch)
    raw = _draft_wire(projection)
    if mutation == "foreign-ref":
        raw["prioritizedDiagnostics"][0]["evidenceRefs"] = ["wae_" + "f" * 32]
    elif mutation == "target-field":
        raw["targetUrl"] = "http://example.invalid/private"
    elif mutation == "execution":
        raw["executionAuthorized"] = True
    else:
        raw["projectionDigest"] = "0" * 64

    with pytest.raises(CodexReconDraftError):
        parse_codex_recon_draft(json.dumps(raw).encode(), expected_projection=projection)


def _turn_events(message: str, *, item_type: str = "agent_message") -> bytes:
    events = [
        {"type": "thread.started", "thread_id": "synthetic-thread"},
        {"type": "turn.started"},
        {"type": "item.completed", "item": {"type": item_type, "text": message}},
        {
            "type": "turn.completed",
            "usage": {
                "input_tokens": 20,
                "cached_input_tokens": 0,
                "output_tokens": 10,
            },
        },
    ]
    return b"\n".join(json.dumps(event).encode() for event in events) + b"\n"


def _started_journal(
    path: Path, projection: CodexReconProjection
) -> tuple[CodexAdvisoryUsageJournal, str]:
    journal = CodexAdvisoryUsageJournal(
        path,
        plan=code_owned_codex_advisory_routing_plan(max_task_tokens=50),
        max_total_tokens=100,
    )
    attempt = journal.reserve(
        stage=CodexAdvisoryStage.RECONNAISSANCE,
        input_digest=projection.projection_digest,
    )
    journal.mark_started(attempt.attempt_id)
    return journal, attempt.attempt_id


def test_recon_turn_admits_draft_and_debits_reported_usage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    projection = _hosted_projection(monkeypatch)
    journal, attempt_id = _started_journal(tmp_path / "usage.sqlite", projection)
    raw = json.dumps(_draft_wire(projection))

    draft = admit_codex_recon_turn(
        _turn_events(raw),
        journal=journal,
        attempt_id=attempt_id,
        expected_projection=projection,
    )

    assert draft.projection_digest == projection.projection_digest
    assert journal.get(attempt_id).state == "succeeded"
    assert journal.charged_tokens() == 30


def test_recon_turn_rejects_tool_event_and_keeps_conservative_charge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    projection = _hosted_projection(monkeypatch)
    journal, attempt_id = _started_journal(tmp_path / "usage.sqlite", projection)

    with pytest.raises(CodexAdvisoryUsageError):
        admit_codex_recon_turn(
            _turn_events("{}", item_type="command_execution"),
            journal=journal,
            attempt_id=attempt_id,
            expected_projection=projection,
        )

    assert journal.get(attempt_id).state == "failed"
    assert journal.charged_tokens() == 50


def test_recon_turn_rejected_draft_still_debits_observed_usage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    projection = _hosted_projection(monkeypatch)
    journal, attempt_id = _started_journal(tmp_path / "usage.sqlite", projection)

    with pytest.raises(CodexReconDraftError):
        admit_codex_recon_turn(
            _turn_events('{"executionAuthorized":true}'),
            journal=journal,
            attempt_id=attempt_id,
            expected_projection=projection,
        )

    assert journal.get(attempt_id).state == "failed"
    assert journal.charged_tokens() == 30
