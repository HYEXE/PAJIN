"""Admit a local Sol-route report draft as an untrusted narrative preview.

The completed campaign is strictly reloaded through the existing Sol input
builder. This module neither invokes Codex nor changes a sealed report,
Finding, SARIF export, PoC, or delivery state.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from hashlib import sha256
from typing import Final, Literal, Self

from pydantic import Field, ValidationError, field_validator, model_validator

from pajin.agentic.codex_routing import CodexAdvisoryStage, CodexAdvisoryWireModel
from pajin.agentic.codex_sol_projection import (
    CodexSolVerifiedInput,
    build_codex_sol_verified_input,
)
from pajin.discovery.canonicalization import discovery_digest
from pajin.reporting.markdown import escape_markdown_text, markdown_code_span
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.web_assessment.governed_campaign_evidence import VerifiedGovernedWebCompletedCampaign

CODEX_SOL_REPORT_DRAFT_API_VERSION: Final = "pajin.dev/codex-sol-report-draft/v1alpha1"
_DRAFT_DOMAIN: Final = "pajin.codex-sol-report-draft/v1alpha1"
_DIGEST_RE: Final = re.compile(r"^[a-f0-9]{64}$")


class CodexSolReportDraftError(ValueError):
    """The local draft or its independently pinned source is inadmissible."""


def _plain_single_line(value: str) -> str:
    if (
        not value
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or any(
            unicodedata.category(character) in {"Cc", "Cf", "Cs"}
            or (character.isspace() and character != " ")
            for character in value
        )
    ):
        raise ValueError("Sol report prose must be normalized single-line text")
    return value


class CodexSolReportFindingNote(CodexAdvisoryWireModel):
    finding_ref: str = Field(alias="findingRef", pattern=r"^csf_[a-f0-9]{32}$")
    note: str = Field(min_length=1, max_length=700)

    @field_validator("note")
    @classmethod
    def require_plain_note(cls, value: str) -> str:
        return _plain_single_line(value)


class CodexSolReportDraft(CodexAdvisoryWireModel):
    """Schema-admitted prose; its content and model origin remain unverified."""

    api_version: Literal["pajin.dev/codex-sol-report-draft/v1alpha1"] = Field(alias="apiVersion")
    kind: Literal["CodexSolReportDraft"]
    stage: Literal[CodexAdvisoryStage.REPORT_DRAFT]
    input_digest: str = Field(alias="inputDigest", pattern=r"^[a-f0-9]{64}$")
    overview: str = Field(min_length=1, max_length=700)
    finding_notes: tuple[CodexSolReportFindingNote, ...] = Field(
        alias="findingNotes", min_length=1, max_length=3, strict=False
    )
    draft_state: Literal["untrusted-local-draft"] = Field(alias="draftState")
    model_origin_verified: Literal[False] = Field(alias="modelOriginVerified")
    target_execution_authorized: Literal[False] = Field(alias="targetExecutionAuthorized")
    finding_authorized: Literal[False] = Field(alias="findingAuthorized")
    graph_write_authorized: Literal[False] = Field(alias="graphWriteAuthorized")
    report_delivery_authorized: Literal[False] = Field(alias="reportDeliveryAuthorized")

    @field_validator("overview")
    @classmethod
    def require_plain_overview(cls, value: str) -> str:
        return _plain_single_line(value)

    @field_validator(
        "model_origin_verified",
        "target_execution_authorized",
        "finding_authorized",
        "graph_write_authorized",
        "report_delivery_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_false(cls, value: object) -> Literal[False]:
        if value is not False:
            raise ValueError("Sol report draft authority markers must be JSON false")
        return False

    @model_validator(mode="after")
    def require_sorted_unique_notes(self) -> Self:
        refs = tuple(item.finding_ref for item in self.finding_notes)
        if refs != tuple(sorted(set(refs))):
            raise ValueError("Sol report notes must have sorted, unique Finding refs")
        return self


@dataclass(frozen=True, slots=True)
class CodexSolReportNarrativeProjection:
    """In-memory preview only; no report writer or authority handle is returned."""

    input_digest: str
    promotion_digest: str
    draft_digest: str
    markdown_sha256: str
    markdown: str
    draft: CodexSolReportDraft
    model_origin_verified: Literal[False] = False
    finding_authorized: Literal[False] = False
    graph_write_authorized: Literal[False] = False
    report_delivery_authorized: Literal[False] = False

    def __post_init__(self) -> None:
        if (
            type(self.draft) is not CodexSolReportDraft
            or any(
                type(value) is not str or _DIGEST_RE.fullmatch(value) is None
                for value in (
                    self.input_digest,
                    self.promotion_digest,
                    self.draft_digest,
                    self.markdown_sha256,
                )
            )
            or self.draft.input_digest != self.input_digest
            or self.draft_digest
            != discovery_digest(_DRAFT_DOMAIN, self.draft.model_dump(mode="json", by_alias=True))
            or type(self.markdown) is not str
            or self.markdown_sha256 != sha256(self.markdown.encode("utf-8")).hexdigest()
            or self.model_origin_verified is not False
            or self.finding_authorized is not False
            or self.graph_write_authorized is not False
            or self.report_delivery_authorized is not False
        ):
            raise ValueError("Sol narrative preview differs from its untrusted draft boundary")


def _parse_draft(content: bytes, expected_input: CodexSolVerifiedInput) -> CodexSolReportDraft:
    raw = parse_strict_json_bytes(
        content,
        label="Codex Sol report draft",
        max_bytes=16 * 1024,
        max_depth=8,
        max_nodes=128,
    )
    if type(raw) is not dict:
        raise ValueError("Codex Sol report draft must be an object")
    draft = CodexSolReportDraft.model_validate(raw)
    if draft.input_digest != expected_input.input_digest:
        raise ValueError("Codex Sol report draft names a different input")
    expected_refs = tuple(signal.finding_ref for signal in expected_input.finding_signals)
    if tuple(item.finding_ref for item in draft.finding_notes) != expected_refs:
        raise ValueError("Codex Sol report draft omits or adds a verified Finding reference")
    return draft


def _render_preview(
    expected_input: CodexSolVerifiedInput,
    draft: CodexSolReportDraft,
) -> str:
    lines = [
        "# Codex Sol route report narrative preview",
        "",
        "> Local, untrusted draft. Model origin and prose accuracy are unverified. "
        "This is not the canonical PAJIN report.",
        "",
        f"- Source input digest: {markdown_code_span(expected_input.input_digest)}",
        f"- Promotion digest: {markdown_code_span(expected_input.promotion_digest)}",
        "- Finding authority: `false`",
        "- Graph write authority: `false`",
        "- External report delivery authorized: `false`",
        "",
        "## Untrusted overview",
        "",
        escape_markdown_text(draft.overview),
        "",
        "## Verified Finding signals and untrusted notes",
        "",
    ]
    for signal, item in zip(expected_input.finding_signals, draft.finding_notes, strict=True):
        lines.extend(
            [
                f"### {markdown_code_span(signal.finding_ref)}",
                "",
                f"- Verified severity: {markdown_code_span(signal.severity.value)}",
                f"- Verified threat class: {markdown_code_span(signal.threat_class)}",
                f"- Untrusted draft note: {escape_markdown_text(item.note)}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def admit_codex_sol_report_draft(
    source: VerifiedGovernedWebCompletedCampaign,
    content: bytes,
    *,
    expected_input_digest: str,
) -> CodexSolReportNarrativeProjection:
    """Strictly reload source and render an in-memory, non-authoritative preview.

    ``expected_input_digest`` must come from the operator's separately retained
    local input pin. A draft's own digest claim cannot establish its source.
    """

    try:
        if (
            type(expected_input_digest) is not str
            or _DIGEST_RE.fullmatch(expected_input_digest) is None
        ):
            raise ValueError("Codex Sol report input requires an independent digest pin")
        expected_input = build_codex_sol_verified_input(
            source,
            stage=CodexAdvisoryStage.REPORT_DRAFT,
        )
        if expected_input.input_digest != expected_input_digest:
            raise ValueError("Codex Sol report input differs from its independent digest pin")
        draft = _parse_draft(content, expected_input)
        markdown = _render_preview(expected_input, draft)
        return CodexSolReportNarrativeProjection(
            input_digest=expected_input.input_digest,
            promotion_digest=expected_input.promotion_digest,
            draft_digest=discovery_digest(
                _DRAFT_DOMAIN,
                draft.model_dump(mode="json", by_alias=True),
            ),
            markdown_sha256=sha256(markdown.encode("utf-8")).hexdigest(),
            markdown=markdown,
            draft=draft,
        )
    except (AttributeError, TypeError, UnicodeError, ValidationError, ValueError) as exc:
        raise CodexSolReportDraftError(
            "Codex Sol report draft is not bound to a strictly reloaded completed campaign"
        ) from exc
