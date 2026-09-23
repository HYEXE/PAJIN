"""Compile one admitted hosted recon turn into an inert local Web proposal.

The independently pinned source and terminal receipt are reloaded before any
model choices are translated. This module performs no model or target I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Final, Literal, Self

from pydantic import Field, field_validator, model_validator

from pajin.agentic.codex_execution import (
    CODEX_DESTINATION,
    build_codex_recon_prompt,
    load_codex_recon_receipt,
)
from pajin.agentic.codex_recon_draft import parse_codex_recon_draft
from pajin.agentic.codex_recon_projection import build_codex_recon_projection
from pajin.agentic.codex_routing import CodexAdvisoryStage, CodexAdvisoryWireModel
from pajin.agentic.codex_usage import CodexAdvisoryUsageJournal, parse_codex_exec_jsonl
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.web_assessment.analysis_proposal import (
    CompiledWebAnalysisProposal,
    WebAnalysisProposalDraft,
    WebAnalysisSnapshot,
    build_web_analysis_snapshot,
    compile_web_analysis_proposal,
    parse_web_analysis_proposal_draft,
    verify_compiled_web_analysis_proposal,
)
from pajin.web_assessment.discovery_artifact import (
    VerifiedAuthenticatedDiscoveryRun,
    load_verified_authenticated_discovery,
)

CODEX_RECON_COMPILATION_API_VERSION: Final = "pajin.dev/codex-recon-compilation/v1alpha1"
_BRIDGE_DOMAIN: Final = "pajin.codex-recon-compilation/v1alpha1"
_HOSTED_DRAFT_DOMAIN: Final = "pajin.codex-recon-admitted-draft/v1alpha1"
_DIGEST_RE: Final = re.compile(r"^[a-f0-9]{64}$")


class CodexReconCompilationError(ValueError):
    """One hosted turn cannot be bound to the current local proposal authority."""


class CodexReconCompilationRecord(CodexAdvisoryWireModel):
    """Digest-only cross-wire lineage; never an action or Finding authority."""

    api_version: Literal["pajin.dev/codex-recon-compilation/v1alpha1"] = Field(alias="apiVersion")
    kind: Literal["CodexReconCompilationRecord"]
    bridge_digest: str = Field(alias="bridgeDigest", pattern=r"^[a-f0-9]{64}$")
    source_run_id: str = Field(alias="sourceRunId", pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=r"^[a-f0-9]{64}$")
    attempt_id: str = Field(alias="attemptId", min_length=1, max_length=64)
    receipt_digest: str = Field(alias="receiptDigest", pattern=r"^[a-f0-9]{64}$")
    authorization_digest: str = Field(alias="authorizationDigest", pattern=r"^[a-f0-9]{64}$")
    prompt_sha256: str = Field(alias="promptSha256", pattern=r"^[a-f0-9]{64}$")
    event_stream_sha256: str = Field(alias="eventStreamSha256", pattern=r"^[a-f0-9]{64}$")
    output_sha256: str = Field(alias="outputSha256", pattern=r"^[a-f0-9]{64}$")
    hosted_projection_digest: str = Field(alias="hostedProjectionDigest", pattern=r"^[a-f0-9]{64}$")
    hosted_draft_digest: str = Field(alias="hostedDraftDigest", pattern=r"^[a-f0-9]{64}$")
    local_snapshot_digest: str = Field(alias="localSnapshotDigest", pattern=r"^[a-f0-9]{64}$")
    local_projection_digest: str = Field(alias="localProjectionDigest", pattern=r"^[a-f0-9]{64}$")
    local_draft_digest: str = Field(alias="localDraftDigest", pattern=r"^[a-f0-9]{64}$")
    compiled_proposal_digest: str = Field(alias="compiledProposalDigest", pattern=r"^[a-f0-9]{64}$")
    compilation_state: Literal["hosted-advisory-compiled-locally-not-authorized"] = Field(
        alias="compilationState"
    )
    diagnostic_rank_is_execution_order: Literal[False] = Field(
        alias="diagnosticRankIsExecutionOrder"
    )
    model_output_authoritative: Literal[False] = Field(alias="modelOutputAuthoritative")
    scope_expansion_authorized: Literal[False] = Field(alias="scopeExpansionAuthorized")
    target_execution_authorized: Literal[False] = Field(alias="targetExecutionAuthorized")
    finding_authorized: Literal[False] = Field(alias="findingAuthorized")
    graph_admission_authorized: Literal[False] = Field(alias="graphAdmissionAuthorized")
    report_delivery_authorized: Literal[False] = Field(alias="reportDeliveryAuthorized")

    @field_validator(
        "diagnostic_rank_is_execution_order",
        "model_output_authoritative",
        "scope_expansion_authorized",
        "target_execution_authorized",
        "finding_authorized",
        "graph_admission_authorized",
        "report_delivery_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> Literal[False]:
        if value is not False:
            raise ValueError("Codex compilation cannot claim authority")
        return False

    @model_validator(mode="after")
    def bind_record(self) -> Self:
        material = self.model_dump(mode="json", by_alias=True, exclude={"bridge_digest"})
        if self.bridge_digest != discovery_digest(_BRIDGE_DOMAIN, material):
            raise ValueError("Codex compilation record digest differs")
        return self


@dataclass(frozen=True, slots=True)
class CodexReconCompilationResult:
    record: CodexReconCompilationRecord
    proposal: CompiledWebAnalysisProposal
    snapshot: WebAnalysisSnapshot
    draft: WebAnalysisProposalDraft


def compile_admitted_codex_recon_proposal(
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    journal: CodexAdvisoryUsageJournal,
    attempt_id: str,
    expected_receipt_digest: str,
) -> CodexReconCompilationResult:
    """Reconcile one terminal no-tool turn and compile only its bounded local meaning."""

    try:
        if type(source) is not VerifiedAuthenticatedDiscoveryRun:
            raise TypeError("Codex compilation requires an exact verified source type")
        if type(journal) is not CodexAdvisoryUsageJournal:
            raise TypeError("Codex compilation requires the exact terminal journal type")
        if (
            type(expected_receipt_digest) is not str
            or _DIGEST_RE.fullmatch(expected_receipt_digest) is None
        ):
            raise ValueError("Codex compilation requires an independent receipt digest")
        current = load_verified_authenticated_discovery(
            source.run_path,
            expected_run_id=expected_source_run_id,
            expected_root_digest=expected_source_root_digest,
        )
        if type(current) is not VerifiedAuthenticatedDiscoveryRun or current != source:
            raise ValueError("Codex compilation source differs from its sealed reload")
        snapshot = build_web_analysis_snapshot(
            current,
            expected_run_id=expected_source_run_id,
            expected_root_digest=expected_source_root_digest,
        )
        hosted_projection = build_codex_recon_projection(
            current,
            expected_run_id=expected_source_run_id,
            expected_root_digest=expected_source_root_digest,
        )
        local_projection = snapshot.model_projection
        if (
            hosted_projection.diagnostics != local_projection.diagnostics
            or hosted_projection.attack_paths != local_projection.attack_paths
            or hosted_projection.evidence_signals != local_projection.evidence_signals
        ):
            raise ValueError("Codex and local projections have different proposal choices")

        receipt = load_codex_recon_receipt(journal, attempt_id)
        prompt_sha256 = sha256(build_codex_recon_prompt(hosted_projection)).hexdigest()
        if (
            receipt.receipt_digest != expected_receipt_digest
            or receipt.attempt_id != attempt_id
            or receipt.terminal_state != "succeeded"
            or receipt.stage is not CodexAdvisoryStage.RECONNAISSANCE
            or receipt.model_id != "gpt-6-luna"
            or receipt.destination != CODEX_DESTINATION
            or receipt.source_run_id != expected_source_run_id
            or receipt.source_root_digest != expected_source_root_digest
            or receipt.projection_digest != hosted_projection.projection_digest
            or receipt.prompt_sha256 != prompt_sha256
            or receipt.tool_events_admitted is not False
            or receipt.output_sha256 is None
            or receipt.draft_digest is None
        ):
            raise ValueError("Codex terminal receipt differs from independent bridge pins")
        streams = journal.terminal_streams(attempt_id)
        if streams is None:
            raise ValueError("Codex terminal streams are absent")
        events, _stderr = streams
        turn = parse_codex_exec_jsonl(events)
        output = turn.message.encode("utf-8")
        hosted_draft = parse_codex_recon_draft(output, expected_projection=hosted_projection)
        hosted_draft_digest = discovery_digest(
            _HOSTED_DRAFT_DOMAIN, hosted_draft.model_dump(mode="json", by_alias=True)
        )
        if (
            receipt.event_stream_sha256 != sha256(events).hexdigest()
            or receipt.output_sha256 != sha256(output).hexdigest()
            or receipt.draft_digest != hosted_draft_digest
            or receipt.thread_id != turn.thread_id
            or receipt.observed_usage is None
            or receipt.observed_usage.total_tokens != turn.usage.total_tokens
        ):
            raise ValueError("Codex hosted draft differs from retained terminal evidence")

        local_payload = {
            "apiVersion": "pajin.dev/web-analysis-proposal-draft/v1alpha1",
            "kind": "WebAnalysisProposalDraft",
            "projectionId": local_projection.projection_id,
            "projectionDigest": local_projection.projection_digest,
            "prioritizedDiagnostics": [
                item.model_dump(mode="json", by_alias=True)
                for item in hosted_draft.prioritized_diagnostics
            ],
            "pathAssessments": [
                item.model_dump(mode="json", by_alias=True)
                for item in hosted_draft.path_assessments
            ],
            "proposalState": "untrusted-model-output-not-authorized",
            "scopeExpansionAuthorized": False,
            "toolRequestCompiled": False,
            "capabilityGranted": False,
            "permitGranted": False,
            "executionAuthorized": False,
            "graphAdmissionAuthorized": False,
            "findingAuthorized": False,
            "reportDeliveryAuthorized": False,
        }
        local_draft = parse_web_analysis_proposal_draft(
            canonical_json_bytes(
                local_payload, label="Codex local draft translation", max_bytes=128 * 1024
            ),
            expected_projection=local_projection,
        )
        compiled = compile_web_analysis_proposal(
            source=current,
            snapshot=snapshot,
            draft=local_draft,
            expected_run_id=expected_source_run_id,
            expected_root_digest=expected_source_root_digest,
        )
        verified = verify_compiled_web_analysis_proposal(
            compiled,
            source=current,
            snapshot=snapshot,
            draft=local_draft,
            expected_run_id=expected_source_run_id,
            expected_root_digest=expected_source_root_digest,
        )
        material = {
            "apiVersion": CODEX_RECON_COMPILATION_API_VERSION,
            "kind": "CodexReconCompilationRecord",
            "sourceRunId": expected_source_run_id,
            "sourceRootDigest": expected_source_root_digest,
            "attemptId": attempt_id,
            "receiptDigest": receipt.receipt_digest,
            "authorizationDigest": receipt.authorization_digest,
            "promptSha256": receipt.prompt_sha256,
            "eventStreamSha256": receipt.event_stream_sha256,
            "outputSha256": receipt.output_sha256,
            "hostedProjectionDigest": hosted_projection.projection_digest,
            "hostedDraftDigest": hosted_draft_digest,
            "localSnapshotDigest": snapshot.snapshot_digest,
            "localProjectionDigest": local_projection.projection_digest,
            "localDraftDigest": verified.source_draft_digest,
            "compiledProposalDigest": verified.proposal_digest,
            "compilationState": "hosted-advisory-compiled-locally-not-authorized",
            "diagnosticRankIsExecutionOrder": False,
            "modelOutputAuthoritative": False,
            "scopeExpansionAuthorized": False,
            "targetExecutionAuthorized": False,
            "findingAuthorized": False,
            "graphAdmissionAuthorized": False,
            "reportDeliveryAuthorized": False,
        }
        record = CodexReconCompilationRecord.model_validate(
            {**material, "bridgeDigest": discovery_digest(_BRIDGE_DOMAIN, material)}
        )
        return CodexReconCompilationResult(
            record=record,
            proposal=verified,
            snapshot=snapshot,
            draft=local_draft,
        )
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, CodexReconCompilationError):
            raise
        raise CodexReconCompilationError(
            "Codex hosted reconnaissance cannot compile under the current sealed authority"
        ) from exc


def verify_codex_recon_compilation(
    result: CodexReconCompilationResult,
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    journal: CodexAdvisoryUsageJournal,
    attempt_id: str,
    expected_receipt_digest: str,
) -> CodexReconCompilationResult:
    """Recompute the bridge and reject a self-consistent but foreign local result."""

    if (
        type(result) is not CodexReconCompilationResult
        or type(result.record) is not CodexReconCompilationRecord
        or type(result.proposal) is not CompiledWebAnalysisProposal
        or type(result.snapshot) is not WebAnalysisSnapshot
        or type(result.draft) is not WebAnalysisProposalDraft
    ):
        raise CodexReconCompilationError("Codex compilation result type differs")
    canonical_record = CodexReconCompilationRecord.model_validate(
        result.record.model_dump(mode="json", by_alias=True)
    )
    canonical_proposal = CompiledWebAnalysisProposal.model_validate(
        result.proposal.model_dump(mode="json", by_alias=True)
    )
    canonical_snapshot = WebAnalysisSnapshot.model_validate(
        result.snapshot.model_dump(mode="json", by_alias=True)
    )
    canonical_draft = WebAnalysisProposalDraft.model_validate(
        result.draft.model_dump(mode="json", by_alias=True)
    )
    rebuilt = compile_admitted_codex_recon_proposal(
        source,
        expected_source_run_id=expected_source_run_id,
        expected_source_root_digest=expected_source_root_digest,
        journal=journal,
        attempt_id=attempt_id,
        expected_receipt_digest=expected_receipt_digest,
    )
    if (
        canonical_record != result.record
        or canonical_proposal != result.proposal
        or canonical_snapshot != result.snapshot
        or canonical_draft != result.draft
        or rebuilt.record != canonical_record
        or rebuilt.proposal != canonical_proposal
        or rebuilt.snapshot != canonical_snapshot
        or rebuilt.draft != canonical_draft
    ):
        raise CodexReconCompilationError("Codex compilation differs from current sealed authority")
    return rebuilt


__all__ = [
    "CODEX_RECON_COMPILATION_API_VERSION",
    "CodexReconCompilationError",
    "CodexReconCompilationRecord",
    "CodexReconCompilationResult",
    "compile_admitted_codex_recon_proposal",
    "verify_codex_recon_compilation",
]
