"""Strict, free-text-free hosted reconnaissance draft admission.

The draft is untrusted model data and has no compilation or execution route.
"""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from typing import Literal, Self

from pydantic import Field, ValidationError, model_validator

from pajin.agentic.codex_recon_projection import CodexReconProjection
from pajin.agentic.codex_routing import CodexAdvisoryStage, CodexAdvisoryWireModel
from pajin.agentic.codex_usage import (
    CodexAdvisoryUsageError,
    CodexAdvisoryUsageJournal,
    parse_codex_exec_jsonl,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.web_assessment.analysis_proposal import (
    WebAnalysisDiagnosticDraft,
    WebAnalysisEvidenceSignal,
    WebAnalysisPathDraft,
)


class CodexReconDraftError(ValueError):
    """Hosted reconnaissance output failed strict proposal-only admission."""


class CodexReconDraft(CodexAdvisoryWireModel):
    api_version: Literal["pajin.dev/codex-recon-draft/v1alpha1"] = Field(alias="apiVersion")
    kind: Literal["CodexReconDraft"]
    projection_digest: str = Field(alias="projectionDigest", pattern=r"^[a-f0-9]{64}$")
    prioritized_diagnostics: tuple[
        WebAnalysisDiagnosticDraft,
        WebAnalysisDiagnosticDraft,
        WebAnalysisDiagnosticDraft,
    ] = Field(alias="prioritizedDiagnostics", strict=False)
    path_assessments: tuple[WebAnalysisPathDraft, WebAnalysisPathDraft] = Field(
        alias="pathAssessments", strict=False
    )
    proposal_state: Literal["untrusted-hosted-draft-not-authorized"] = Field(alias="proposalState")
    scope_expansion_authorized: Literal[False] = Field(alias="scopeExpansionAuthorized")
    tool_request_compiled: Literal[False] = Field(alias="toolRequestCompiled")
    capability_granted: Literal[False] = Field(alias="capabilityGranted")
    permit_granted: Literal[False] = Field(alias="permitGranted")
    execution_authorized: Literal[False] = Field(alias="executionAuthorized")
    graph_admission_authorized: Literal[False] = Field(alias="graphAdmissionAuthorized")
    finding_authorized: Literal[False] = Field(alias="findingAuthorized")
    report_delivery_authorized: Literal[False] = Field(alias="reportDeliveryAuthorized")

    @model_validator(mode="after")
    def require_closed_catalog(self) -> Self:
        if tuple(item.rank for item in self.prioritized_diagnostics) != (1, 2, 3):
            raise ValueError("Hosted recon draft ranks must be contiguous")
        if {item.diagnostic_id for item in self.prioritized_diagnostics} != {
            "sql-login",
            "object-access",
            "dom-xss",
        }:
            raise ValueError("Hosted recon draft must rank every code-owned diagnostic")
        if tuple(item.issue_sequence for item in self.path_assessments) != (
            ("sql-login", "object-access"),
            ("dom-xss",),
        ):
            raise ValueError("Hosted recon draft must assess every code-owned path")
        return self


def parse_codex_recon_draft(
    content: bytes,
    *,
    expected_projection: CodexReconProjection,
) -> CodexReconDraft:
    """Admit a bounded draft only against the exact locally rebuilt projection."""

    try:
        raw = parse_strict_json_bytes(
            content,
            label="Codex hosted recon draft",
            max_bytes=16 * 1024,
            max_depth=12,
            max_nodes=512,
        )
        if type(raw) is not dict:
            raise ValueError("Codex recon draft must be an object")
        projection = CodexReconProjection.model_validate(
            expected_projection.model_dump(mode="json", by_alias=True)
        )
        draft = CodexReconDraft.model_validate(raw)
        if draft.projection_digest != projection.projection_digest:
            raise ValueError("Codex recon draft names a different projection")
        projected_diagnostics = {item.diagnostic_id: item for item in projection.diagnostics}
        projected_paths = {item.issue_sequence: item for item in projection.attack_paths}
        signal_by_ref = {item.evidence_ref: item for item in projection.evidence_signals}
        for item in draft.prioritized_diagnostics:
            projected = projected_diagnostics[item.diagnostic_id]
            if (
                item.catalog_entry_id != projected.catalog_entry_id
                or item.hypothesis_id not in projected.allowed_hypothesis_ids
            ):
                raise ValueError("Codex recon diagnostic differs from the exact projection")
            _require_supported_refs(item.evidence_refs, item.catalog_entry_id, signal_by_ref)
        for path_item in draft.path_assessments:
            projected_path = projected_paths[path_item.issue_sequence]
            if (
                path_item.catalog_entry_id != projected_path.catalog_entry_id
                or path_item.hypothesis_id not in projected_path.allowed_hypothesis_ids
                or path_item.disposition not in projected_path.allowed_dispositions
            ):
                raise ValueError("Codex recon path differs from the exact projection")
            _require_supported_refs(
                path_item.evidence_refs, path_item.catalog_entry_id, signal_by_ref
            )
        return draft
    except (AttributeError, TypeError, UnicodeError, ValidationError, ValueError) as exc:
        raise CodexReconDraftError("Codex recon draft is not an exact inert proposal") from exc


def _require_supported_refs(
    refs: tuple[str, ...],
    catalog_entry_id: str,
    signal_by_ref: Mapping[str, WebAnalysisEvidenceSignal],
) -> None:
    for ref in refs:
        signal = signal_by_ref.get(ref)
        if signal is None or catalog_entry_id not in signal.supports_catalog_entries:
            raise ValueError("Codex recon draft references unsupported Evidence")


def admit_codex_recon_turn(
    content: bytes,
    *,
    journal: CodexAdvisoryUsageJournal,
    attempt_id: str,
    expected_projection: CodexReconProjection,
) -> CodexReconDraft:
    """Settle one already-started turn after strict event and draft admission."""

    attempt = journal.get(attempt_id)
    projection = CodexReconProjection.model_validate(
        expected_projection.model_dump(mode="json", by_alias=True)
    )
    if (
        attempt.state != "started-uncertain"
        or attempt.stage is not CodexAdvisoryStage.RECONNAISSANCE
        or attempt.input_digest != projection.projection_digest
    ):
        raise CodexReconDraftError("Codex recon attempt differs from its reserved input")
    try:
        turn = parse_codex_exec_jsonl(content)
    except CodexAdvisoryUsageError:
        journal.finalize(attempt_id, usage=None, output_digest=None, success=False)
        raise
    output = turn.message.encode("utf-8")
    output_digest = sha256(output).hexdigest()
    try:
        draft = parse_codex_recon_draft(output, expected_projection=projection)
    except CodexReconDraftError:
        journal.finalize(
            attempt_id,
            usage=turn.usage,
            output_digest=output_digest,
            success=False,
        )
        raise
    journal.finalize(
        attempt_id,
        usage=turn.usage,
        output_digest=output_digest,
        success=True,
    )
    return draft
