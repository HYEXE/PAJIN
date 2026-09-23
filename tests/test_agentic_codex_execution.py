"""Offline authorization, exact transfer, and terminal receipt checks."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import ValidationError

import pajin.agentic.codex_execution as execution
import pajin.agentic.codex_sol_projection as sol_projection
from pajin.agentic.codex_recon_draft import CodexReconDraft
from pajin.agentic.codex_recon_projection import CodexReconProjection
from pajin.agentic.codex_routing import (
    CodexAdvisoryStage,
    code_owned_codex_advisory_routing_plan,
)
from pajin.agentic.codex_usage import CodexAdvisoryUsageError, CodexAdvisoryUsageJournal
from pajin.discovery.canonicalization import discovery_digest
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun
from pajin.web_assessment.governed_campaign_evidence import VerifiedGovernedWebCompletedCampaign

_SOURCE_RUN_ID = "run_20260915T020000Z_a1b2c3d4"
_SOURCE_ROOT_DIGEST = "c" * 64


def _synthetic_projection() -> CodexReconProjection:
    diagnostics = [
        (
            "sql-login",
            "pajin.web-analysis.diagnostic.sql-login.v1",
            "pajin.web-analysis.hypothesis.sql-login-authentication-bypass.v1",
        ),
        (
            "object-access",
            "pajin.web-analysis.diagnostic.object-access.v1",
            "pajin.web-analysis.hypothesis.cross-account-object-access.v1",
        ),
        (
            "dom-xss",
            "pajin.web-analysis.diagnostic.dom-xss.v1",
            "pajin.web-analysis.hypothesis.client-marker-execution.v1",
        ),
    ]
    paths = [
        (
            "pajin.web-analysis.path.sql-login-object-access.v1",
            ["sql-login", "object-access"],
            "pajin.web-analysis.hypothesis.authentication-to-object-access.v1",
        ),
        (
            "pajin.web-analysis.path.dom-xss.v1",
            ["dom-xss"],
            "pajin.web-analysis.hypothesis.client-marker-impact.v1",
        ),
    ]
    payload = {
        "apiVersion": "pajin.dev/codex-recon-projection/v1alpha1",
        "kind": "CodexReconProjection",
        "diagnostics": [
            {"diagnosticId": item, "catalogEntryId": entry, "allowedHypothesisIds": [hypothesis]}
            for item, entry, hypothesis in diagnostics
        ],
        "attackPaths": [
            {
                "catalogEntryId": entry,
                "issueSequence": issues,
                "allowedHypothesisIds": [hypothesis],
                "allowedDispositions": ["investigate", "insufficient-evidence"],
            }
            for entry, issues, hypothesis in paths
        ],
        "evidenceSignals": [
            {
                "evidenceRef": "wae_" + "a" * 32,
                "signalKind": "discovered-route-count",
                "countBucket": "two-to-five",
                "supportsCatalogEntries": sorted(
                    [item[1] for item in diagnostics] + [item[0] for item in paths]
                ),
            }
        ],
        "sourceAnchorsEmbedded": False,
        "targetContentEmbedded": False,
        "toolAccessAuthorized": False,
        "executionAuthorized": False,
        "findingAuthorized": False,
        "publicationAuthorized": False,
    }
    return CodexReconProjection.model_validate(
        {
            **payload,
            "projectionDigest": discovery_digest("pajin.codex-recon-projection/v1alpha1", payload),
        }
    )


def _synthetic_draft(projection: CodexReconProjection) -> CodexReconDraft:
    ref = projection.evidence_signals[0].evidence_ref
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
    )


def _authorization(projection: CodexReconProjection) -> execution.CodexReconTransferAuthorization:
    now = datetime.now(UTC)
    payload = {
        "apiVersion": execution.CODEX_RECON_TRANSFER_API_VERSION,
        "kind": "CodexReconTransferAuthorization",
        "stage": "reconnaissance",
        "destination": execution.CODEX_DESTINATION,
        "modelId": "gpt-6-luna",
        "sourceRunId": _SOURCE_RUN_ID,
        "sourceRootDigest": _SOURCE_ROOT_DIGEST,
        "projectionDigest": projection.projection_digest,
        "promptSha256": sha256(execution.build_codex_recon_prompt(projection)).hexdigest(),
        "clientVersion": execution.CODEX_CLIENT_VERSION,
        "clientSha256": execution.CODEX_CLIENT_SHA256,
        "maxAttempts": 1,
        "authorizedAt": now.isoformat().replace("+00:00", "Z"),
        "expiresAt": (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "hostedTransferAuthorized": True,
        "toolAccessAuthorized": False,
        "targetExecutionAuthorized": False,
    }
    return execution.CodexReconTransferAuthorization.model_validate_json(
        json.dumps(
            {
                **payload,
                "authorizationDigest": discovery_digest(
                    "pajin.codex-recon-transfer-authorization/v1alpha1", payload
                ),
            }
        )
    )


def _events(message: str, *, tool: bool = False) -> bytes:
    events: list[dict[str, object]] = [
        {"type": "thread.started", "thread_id": "synthetic-thread"},
        {"type": "turn.started"},
    ]
    if tool:
        events.append(
            {"type": "item.completed", "item": {"type": "command_execution", "command": "cat"}}
        )
    else:
        events.append(
            {"type": "item.completed", "item": {"type": "agent_message", "text": message}}
        )
    events.append(
        {
            "type": "turn.completed",
            "usage": {"input_tokens": 20, "cached_input_tokens": 0, "output_tokens": 10},
        }
    )
    return b"\n".join(json.dumps(event).encode() for event in events) + b"\n"


def _journal(tmp_path: Path) -> CodexAdvisoryUsageJournal:
    return CodexAdvisoryUsageJournal(
        tmp_path / "codex.sqlite",
        plan=code_owned_codex_advisory_routing_plan(max_task_tokens=100),
        max_total_tokens=100,
    )


def test_unregistered_transfer_fails_before_binary_or_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projection = _synthetic_projection()
    monkeypatch.setattr(
        execution, "build_codex_recon_projection", lambda *_args, **_kwargs: projection
    )
    journal = _journal(tmp_path)
    with pytest.raises(PermissionError, match="operator-admitted"):
        execution.execute_codex_recon_once(
            cast(VerifiedAuthenticatedDiscoveryRun, object()),
            projection,
            expected_source_run_id=_SOURCE_RUN_ID,
            expected_source_root_digest=_SOURCE_ROOT_DIGEST,
            authorization=_authorization(projection),
            authority=execution.CodexReconTransferRegistry(()),
            journal=journal,
            binary=tmp_path / "nonexistent-codex",
            private_root=tmp_path,
        )
    assert journal.charged_tokens() == 0


def test_reloaded_source_mismatch_blocks_before_hosted_transfer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projection = _synthetic_projection()
    monkeypatch.setattr(
        execution, "build_codex_recon_projection", lambda *_args, **_kwargs: object()
    )
    journal = _journal(tmp_path)
    authorization = _authorization(projection)
    with pytest.raises(execution.CodexExecutionError, match="strictly reloaded source"):
        execution.execute_codex_recon_once(
            cast(VerifiedAuthenticatedDiscoveryRun, object()),
            projection,
            expected_source_run_id=_SOURCE_RUN_ID,
            expected_source_root_digest=_SOURCE_ROOT_DIGEST,
            authorization=authorization,
            authority=execution.CodexReconTransferRegistry((authorization,)),
            journal=journal,
            binary=tmp_path / "nonexistent-codex",
            private_root=tmp_path,
        )
    assert journal.charged_tokens() == 0


def test_pinned_output_schema_has_array_items_and_closed_objects() -> None:
    schema = execution._recon_output_schema(_synthetic_projection())
    properties = schema["properties"]
    assert isinstance(properties, dict)
    assert properties["prioritizedDiagnostics"]["items"]["additionalProperties"] is False
    assert properties["pathAssessments"]["items"]["properties"]["evidenceRefs"]["items"]


@pytest.mark.parametrize("tool", [False, True])
def test_terminal_attempt_retains_receipt_and_rejects_tool_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: bool
) -> None:
    projection = _synthetic_projection()
    authorization = _authorization(projection)
    journal = _journal(tmp_path)
    started_at = datetime.now(UTC)
    stdout = _events(_synthetic_draft(projection).model_dump_json(by_alias=True), tool=tool)

    def preflight(
        *_args: object,
    ) -> tuple[
        CodexReconProjection,
        execution.CodexReconTransferAuthorization,
        bytes,
        Path,
        Path,
    ]:
        return (
            projection,
            authorization,
            execution.build_codex_recon_prompt(projection),
            Path("/bin/echo"),
            Path("/dev/null"),
        )

    def run_client(**kwargs: object) -> execution._ClientRecord:
        attempt_id = kwargs["attempt_id"]
        assert isinstance(attempt_id, str)
        journal.mark_started(attempt_id)
        return execution._ClientRecord(
            command=("codex", "exec"),
            profile_bytes=b"synthetic-profile",
            stdout=stdout,
            stderr=b"",
            exit_code=0,
            timed_out=False,
            scratch_cleaned=True,
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )

    monkeypatch.setattr(execution, "_preflight", preflight)
    monkeypatch.setattr(execution, "_run_isolated_client", run_client)
    result = execution.execute_codex_recon_once(
        cast(VerifiedAuthenticatedDiscoveryRun, object()),
        projection,
        expected_source_run_id=_SOURCE_RUN_ID,
        expected_source_root_digest=_SOURCE_ROOT_DIGEST,
        authorization=authorization,
        authority=execution.CodexReconTransferRegistry((authorization,)),
        journal=journal,
        binary=Path("/bin/echo"),
        private_root=tmp_path,
    )
    assert result.receipt.terminal_state == ("failed" if tool else "succeeded")
    assert (result.draft is None) is tool
    assert journal.terminal_receipt(result.receipt.attempt_id) is not None
    assert journal.terminal_streams(result.receipt.attempt_id) == (stdout, b"")
    assert execution.load_codex_recon_receipt(journal, result.receipt.attempt_id) == result.receipt
    if tool:
        with pytest.raises(CodexAdvisoryUsageError, match="unresolved usage"):
            journal.reserve(
                stage=CodexAdvisoryStage.REPORT_DRAFT,
                input_digest="b" * 64,
            )


def test_receipt_reload_rejects_changed_retained_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    projection = _synthetic_projection()
    authorization = _authorization(projection)
    journal = _journal(tmp_path)
    stdout = _events(_synthetic_draft(projection).model_dump_json(by_alias=True))

    def preflight(
        *_args: object,
    ) -> tuple[
        CodexReconProjection,
        execution.CodexReconTransferAuthorization,
        bytes,
        Path,
        Path,
    ]:
        return (
            projection,
            authorization,
            execution.build_codex_recon_prompt(projection),
            Path("/bin/echo"),
            Path("/dev/null"),
        )

    def run_client(**kwargs: object) -> execution._ClientRecord:
        attempt_id = kwargs["attempt_id"]
        assert isinstance(attempt_id, str)
        journal.mark_started(attempt_id)
        now = datetime.now(UTC)
        return execution._ClientRecord(
            command=("codex", "exec"),
            profile_bytes=b"synthetic-profile",
            stdout=stdout,
            stderr=b"",
            exit_code=0,
            timed_out=False,
            scratch_cleaned=True,
            started_at=now,
            completed_at=now,
        )

    monkeypatch.setattr(execution, "_preflight", preflight)
    monkeypatch.setattr(execution, "_run_isolated_client", run_client)
    result = execution.execute_codex_recon_once(
        cast(VerifiedAuthenticatedDiscoveryRun, object()),
        projection,
        expected_source_run_id=_SOURCE_RUN_ID,
        expected_source_root_digest=_SOURCE_ROOT_DIGEST,
        authorization=authorization,
        authority=execution.CodexReconTransferRegistry((authorization,)),
        journal=journal,
        binary=Path("/bin/echo"),
        private_root=tmp_path,
    )
    changed = stdout.replace(b"synthetic-thread", b"different-thread", 1)
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE terminal_receipts SET event_sha256 = ?, event_bytes = ? WHERE attempt_id = ?",
            (sha256(changed).hexdigest(), changed, result.receipt.attempt_id),
        )
    with pytest.raises(execution.CodexExecutionError, match="journal evidence"):
        execution.load_codex_recon_receipt(journal, result.receipt.attempt_id)


def test_sol_penetration_input_is_closed_and_stays_nonexecuting() -> None:
    projection = _synthetic_projection()
    source = sol_projection.build_codex_sol_penetration_input(
        projection, _synthetic_draft(projection)
    )
    assert source.stage is CodexAdvisoryStage.PENETRATION_REVIEW
    assert source.target_content_embedded is False
    assert source.target_execution_authorized is False
    raw = source.model_dump(mode="json", by_alias=True)
    raw["targetUrl"] = "https://example.invalid/private"
    with pytest.raises(ValidationError):
        sol_projection.CodexSolPenetrationInput.model_validate(raw)


def test_sol_verified_input_requires_loaded_completed_campaign() -> None:
    with pytest.raises(ValueError, match="strictly loaded completed campaign"):
        sol_projection.build_codex_sol_verified_input(
            cast(VerifiedGovernedWebCompletedCampaign, SimpleNamespace()),
            stage=CodexAdvisoryStage.VULNERABILITY_ANALYSIS,
        )


def test_sol_verified_wire_has_no_target_or_raw_evidence_field() -> None:
    payload = {
        "apiVersion": sol_projection.CODEX_SOL_VERIFIED_INPUT_API_VERSION,
        "kind": "CodexSolVerifiedInput",
        "stage": "report-draft",
        "promotionDigest": "a" * 64,
        "findingSignals": [
            {
                "findingRef": "csf_" + "b" * 32,
                "severity": "high",
                "threatClass": "CWE-89",
                "independentlyVerified": True,
            }
        ],
        "targetContentEmbedded": False,
        "sourceAnchorsEmbedded": False,
        "rawEvidenceEmbedded": False,
        "reportDeliveryAuthorized": False,
        "findingAuthorized": False,
    }
    source = sol_projection.CodexSolVerifiedInput.model_validate(
        {
            **payload,
            "inputDigest": discovery_digest("pajin.codex-sol-verified-input/v1alpha1", payload),
        }
    )
    assert source.finding_signals[0].severity.value == "high"
    with pytest.raises(ValidationError):
        sol_projection.CodexSolVerifiedInput.model_validate(
            {
                **source.model_dump(mode="json", by_alias=True),
                "targetUrl": "https://example.invalid",
            }
        )
