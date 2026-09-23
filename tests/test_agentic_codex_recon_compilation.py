"""Offline hosted-recon lineage cannot become Web execution authority."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

import pajin.agentic.codex_execution as execution
import pajin.agentic.codex_recon_compilation as bridge
import pajin.web_assessment.analysis_proposal as analysis_proposal
from pajin.agentic.codex_recon_draft import CodexReconDraft
from pajin.agentic.codex_recon_projection import CodexReconProjection
from pajin.agentic.codex_routing import code_owned_codex_advisory_routing_plan
from pajin.agentic.codex_usage import CodexAdvisoryUsageJournal
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun
from tests.test_web_analysis_proposal import _synthetic_loader, _verified_source


def _draft(projection: CodexReconProjection) -> CodexReconDraft:
    def ref_for(entry: str) -> str:
        return next(
            signal.evidence_ref
            for signal in projection.evidence_signals
            if entry in signal.supports_catalog_entries
        )

    return CodexReconDraft.model_validate(
        {
            "apiVersion": "pajin.dev/codex-recon-draft/v1alpha1",
            "kind": "CodexReconDraft",
            "projectionDigest": projection.projection_digest,
            "prioritizedDiagnostics": [
                {
                    "rank": rank,
                    "diagnosticId": item.diagnostic_id,
                    "catalogEntryId": item.catalog_entry_id,
                    "hypothesisId": item.allowed_hypothesis_ids[0],
                    "evidenceRefs": [ref_for(item.catalog_entry_id)],
                }
                for rank, item in enumerate(projection.diagnostics, start=1)
            ],
            "pathAssessments": [
                {
                    "catalogEntryId": item.catalog_entry_id,
                    "hypothesisId": item.allowed_hypothesis_ids[0],
                    "issueSequence": list(item.issue_sequence),
                    "disposition": "investigate",
                    "evidenceRefs": [ref_for(item.catalog_entry_id)],
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
    )


def _events(message: str, *, tool: bool = False) -> bytes:
    events: list[dict[str, object]] = [
        {"type": "thread.started", "thread_id": "synthetic-thread"},
        {"type": "turn.started"},
        {
            "type": "item.completed",
            "item": (
                {"type": "command_execution", "command": "never-run"}
                if tool
                else {"type": "agent_message", "text": message}
            ),
        },
        {
            "type": "turn.completed",
            "usage": {"input_tokens": 20, "cached_input_tokens": 0, "output_tokens": 10},
        },
    ]
    return b"\n".join(json.dumps(event).encode() for event in events) + b"\n"


def _setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    tool: bool = False,
) -> tuple[VerifiedAuthenticatedDiscoveryRun, CodexAdvisoryUsageJournal, str, str]:
    source = _verified_source()
    loader = _synthetic_loader(source)
    monkeypatch.setattr(bridge, "load_verified_authenticated_discovery", loader)
    monkeypatch.setattr(analysis_proposal, "load_verified_authenticated_discovery", loader)
    anchors = {
        "expected_run_id": source.verification.run_id,
        "expected_root_digest": source.verification.root_digest,
    }
    projection = bridge.build_codex_recon_projection(source, **anchors)
    events = _events(_draft(projection).model_dump_json(by_alias=True), tool=tool)
    journal = CodexAdvisoryUsageJournal(
        tmp_path / "codex.sqlite",
        plan=code_owned_codex_advisory_routing_plan(max_task_tokens=100),
        max_total_tokens=100,
    )
    started_at = datetime.now(UTC)
    prompt = execution.build_codex_recon_prompt(projection)
    authorization_payload = {
        "apiVersion": execution.CODEX_RECON_TRANSFER_API_VERSION,
        "kind": "CodexReconTransferAuthorization",
        "stage": "reconnaissance",
        "destination": execution.CODEX_DESTINATION,
        "modelId": "gpt-6-luna",
        "sourceRunId": source.verification.run_id,
        "sourceRootDigest": source.verification.root_digest,
        "projectionDigest": projection.projection_digest,
        "promptSha256": sha256(prompt).hexdigest(),
        "clientVersion": execution.CODEX_CLIENT_VERSION,
        "clientSha256": execution.CODEX_CLIENT_SHA256,
        "maxAttempts": 1,
        "authorizedAt": started_at.isoformat().replace("+00:00", "Z"),
        "expiresAt": (started_at + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "hostedTransferAuthorized": True,
        "toolAccessAuthorized": False,
        "targetExecutionAuthorized": False,
    }
    authorization = execution.CodexReconTransferAuthorization.model_validate_json(
        canonical_json_bytes(
            {
                **authorization_payload,
                "authorizationDigest": discovery_digest(
                    "pajin.codex-recon-transfer-authorization/v1alpha1",
                    authorization_payload,
                ),
            },
            label="synthetic Codex authorization",
        )
    )

    def preflight(*_args: object) -> tuple[object, ...]:
        return (
            projection,
            authorization,
            prompt,
            tmp_path / "unused-client",
            tmp_path / "unused-auth",
        )

    def run_client(**kwargs: object) -> execution._ClientRecord:
        attempt_id = kwargs["attempt_id"]
        assert isinstance(attempt_id, str)
        journal.mark_started(attempt_id)
        return execution._ClientRecord(
            command=("synthetic-client", "exec"),
            profile_bytes=b"synthetic-isolation",
            stdout=events,
            stderr=b"",
            exit_code=0,
            timed_out=False,
            scratch_cleaned=True,
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )

    monkeypatch.setattr(execution, "_preflight", preflight)
    monkeypatch.setattr(execution, "_run_isolated_client", run_client)
    completed = execution.execute_codex_recon_once(
        source,
        projection,
        expected_source_run_id=anchors["expected_run_id"],
        expected_source_root_digest=anchors["expected_root_digest"],
        authorization=authorization,
        authority=execution.CodexReconTransferRegistry((authorization,)),
        journal=journal,
        binary=tmp_path / "unused-client",
        private_root=tmp_path,
    )
    return source, journal, completed.receipt.attempt_id, completed.receipt.receipt_digest


def _compile(
    source: VerifiedAuthenticatedDiscoveryRun,
    journal: CodexAdvisoryUsageJournal,
    attempt_id: str,
    receipt_digest: str,
) -> bridge.CodexReconCompilationResult:
    return bridge.compile_admitted_codex_recon_proposal(
        source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        journal=journal,
        attempt_id=attempt_id,
        expected_receipt_digest=receipt_digest,
    )


def test_successful_no_tool_turn_compiles_to_inert_local_proposal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, journal, attempt_id, receipt_digest = _setup(tmp_path, monkeypatch)
    result = _compile(source, journal, attempt_id, receipt_digest)
    verified = bridge.verify_codex_recon_compilation(
        result,
        source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        journal=journal,
        attempt_id=attempt_id,
        expected_receipt_digest=receipt_digest,
    )

    assert verified == result
    assert result.record.api_version == bridge.CODEX_RECON_COMPILATION_API_VERSION
    assert result.record.local_projection_digest != result.record.hosted_projection_digest
    assert result.snapshot.source_run_id == source.verification.run_id
    assert result.snapshot.snapshot_digest == result.proposal.source_snapshot_digest
    assert result.draft.projection_digest == result.snapshot.model_projection.projection_digest
    assert result.draft.projection_id == result.snapshot.model_projection.projection_id
    assert result.record.local_draft_digest == result.proposal.source_draft_digest
    assert result.record.compiled_proposal_digest == result.proposal.proposal_digest
    assert result.record.diagnostic_rank_is_execution_order is False
    assert result.record.target_execution_authorized is False
    assert result.record.finding_authorized is False
    assert result.record.graph_admission_authorized is False
    assert result.record.report_delivery_authorized is False
    assert result.proposal.compilation_state == "compiled-proposal-not-authorized"
    assert result.proposal.execution_authorized is False


@pytest.mark.parametrize("wrong_pin", ["source-root", "receipt-digest", "attempt-id"])
def test_bridge_rejects_foreign_independent_pins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wrong_pin: str
) -> None:
    source, journal, attempt_id, receipt_digest = _setup(tmp_path, monkeypatch)
    kwargs = {
        "expected_source_run_id": source.verification.run_id,
        "expected_source_root_digest": source.verification.root_digest,
        "journal": journal,
        "attempt_id": attempt_id,
        "expected_receipt_digest": receipt_digest,
    }
    if wrong_pin == "source-root":
        kwargs["expected_source_root_digest"] = "b" * 64
    elif wrong_pin == "receipt-digest":
        kwargs["expected_receipt_digest"] = "b" * 64
    else:
        kwargs["attempt_id"] = "foreign-attempt"
    with pytest.raises(bridge.CodexReconCompilationError):
        bridge.compile_admitted_codex_recon_proposal(source, **kwargs)


def test_bridge_checks_hosted_draft_digest_missing_from_generic_receipt_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, journal, attempt_id, _receipt_digest = _setup(tmp_path, monkeypatch)
    receipt = execution.load_codex_recon_receipt(journal, attempt_id)
    material = receipt.model_dump(mode="json", by_alias=True, exclude={"receipt_digest"})
    material["draftDigest"] = "b" * 64
    changed = {
        **material,
        "receiptDigest": discovery_digest("pajin.codex-recon-execution-receipt/v1alpha1", material),
    }
    changed_bytes = canonical_json_bytes(changed, label="synthetic changed receipt")
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE terminal_receipts SET receipt_sha256 = ?, receipt_bytes = ? "
            "WHERE attempt_id = ?",
            (sha256(changed_bytes).hexdigest(), changed_bytes, attempt_id),
        )
    assert execution.load_codex_recon_receipt(journal, attempt_id).draft_digest == "b" * 64
    with pytest.raises(bridge.CodexReconCompilationError):
        _compile(source, journal, attempt_id, changed["receiptDigest"])


def test_tool_event_is_not_compilable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, journal, attempt_id, receipt_digest = _setup(tmp_path, monkeypatch, tool=True)
    assert execution.load_codex_recon_receipt(journal, attempt_id).terminal_state == "failed"
    with pytest.raises(bridge.CodexReconCompilationError):
        _compile(source, journal, attempt_id, receipt_digest)


def test_projection_choice_drift_fails_before_local_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, journal, attempt_id, receipt_digest = _setup(tmp_path, monkeypatch)
    snapshot = bridge.build_web_analysis_snapshot(
        source,
        expected_run_id=source.verification.run_id,
        expected_root_digest=source.verification.root_digest,
    )
    signal = snapshot.model_projection.evidence_signals[0].model_copy(
        update={"count_bucket": "six-to-twenty"}
    )
    projection = snapshot.model_projection.model_copy(
        update={"evidence_signals": (signal, *snapshot.model_projection.evidence_signals[1:])}
    )
    monkeypatch.setattr(
        bridge,
        "build_web_analysis_snapshot",
        lambda *_args, **_kwargs: snapshot.model_copy(update={"model_projection": projection}),
    )
    with pytest.raises(bridge.CodexReconCompilationError):
        _compile(source, journal, attempt_id, receipt_digest)


def test_bridge_record_cannot_claim_authority_or_verify_foreign_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, journal, attempt_id, receipt_digest = _setup(tmp_path, monkeypatch)
    result = _compile(source, journal, attempt_id, receipt_digest)
    raw = result.record.model_dump(mode="json", by_alias=True, exclude={"bridge_digest"})
    raw["findingAuthorized"] = True
    with pytest.raises(ValidationError):
        bridge.CodexReconCompilationRecord.model_validate(
            {**raw, "bridgeDigest": discovery_digest("pajin.codex-recon-compilation/v1alpha1", raw)}
        )

    foreign = replace(
        result,
        record=result.record.model_copy(update={"receipt_digest": "b" * 64}),
    )
    with pytest.raises((bridge.CodexReconCompilationError, ValidationError)):
        bridge.verify_codex_recon_compilation(
            foreign,
            source,
            expected_source_run_id=source.verification.run_id,
            expected_source_root_digest=source.verification.root_digest,
            journal=journal,
            attempt_id=attempt_id,
            expected_receipt_digest=receipt_digest,
        )

    for altered in (
        replace(result, snapshot=result.snapshot.model_copy(update={"snapshot_digest": "b" * 64})),
        replace(result, draft=result.draft.model_copy(update={"projection_digest": "b" * 64})),
    ):
        with pytest.raises((bridge.CodexReconCompilationError, ValidationError)):
            bridge.verify_codex_recon_compilation(
                altered,
                source,
                expected_source_run_id=source.verification.run_id,
                expected_source_root_digest=source.verification.root_digest,
                journal=journal,
                attempt_id=attempt_id,
                expected_receipt_digest=receipt_digest,
            )
