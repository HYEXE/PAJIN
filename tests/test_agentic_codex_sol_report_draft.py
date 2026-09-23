from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from typing import cast

import pytest

import pajin.agentic.codex_sol_report_draft as report_draft
from pajin.agentic.codex_routing import CodexAdvisoryStage
from pajin.agentic.codex_sol_projection import CodexSolVerifiedInput
from pajin.discovery.canonicalization import discovery_digest
from pajin.web_assessment.governed_campaign_evidence import VerifiedGovernedWebCompletedCampaign


def _verified_input() -> CodexSolVerifiedInput:
    payload = {
        "apiVersion": "pajin.dev/codex-sol-verified-input/v1alpha1",
        "kind": "CodexSolVerifiedInput",
        "stage": "report-draft",
        "promotionDigest": "a" * 64,
        "findingSignals": [
            {
                "findingRef": "csf_" + suffix * 32,
                "severity": severity,
                "threatClass": threat_class,
                "independentlyVerified": True,
            }
            for suffix, severity, threat_class in (
                ("b", "high", "CWE-89"),
                ("c", "medium", "CWE-639"),
                ("d", "low", "CWE-79"),
            )
        ],
        "targetContentEmbedded": False,
        "sourceAnchorsEmbedded": False,
        "rawEvidenceEmbedded": False,
        "reportDeliveryAuthorized": False,
        "findingAuthorized": False,
    }
    return CodexSolVerifiedInput.model_validate(
        {
            **payload,
            "inputDigest": discovery_digest("pajin.codex-sol-verified-input/v1alpha1", payload),
        }
    )


def _draft_payload(source: CodexSolVerifiedInput) -> dict[str, object]:
    return {
        "apiVersion": report_draft.CODEX_SOL_REPORT_DRAFT_API_VERSION,
        "kind": "CodexSolReportDraft",
        "stage": "report-draft",
        "inputDigest": source.input_digest,
        "overview": "Review the three verified Finding signals.",
        "findingNotes": [
            {"findingRef": signal.finding_ref, "note": "Review the canonical PAJIN Finding."}
            for signal in source.finding_signals
        ],
        "draftState": "untrusted-local-draft",
        "modelOriginVerified": False,
        "targetExecutionAuthorized": False,
        "findingAuthorized": False,
        "graphWriteAuthorized": False,
        "reportDeliveryAuthorized": False,
    }


def _encoded(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")


def _admit(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object] | bytes,
    *,
    source: CodexSolVerifiedInput | None = None,
    expected_input_digest: str | None = None,
) -> report_draft.CodexSolReportNarrativeProjection:
    verified = source or _verified_input()
    source_handle = cast(VerifiedGovernedWebCompletedCampaign, object())
    rebuilt = []

    def rebuild(
        received: VerifiedGovernedWebCompletedCampaign,
        *,
        stage: CodexAdvisoryStage,
    ) -> CodexSolVerifiedInput:
        rebuilt.append((received, stage))
        return verified

    monkeypatch.setattr(report_draft, "build_codex_sol_verified_input", rebuild)
    result = report_draft.admit_codex_sol_report_draft(
        source_handle,
        payload if isinstance(payload, bytes) else _encoded(payload),
        expected_input_digest=expected_input_digest or verified.input_digest,
    )
    assert rebuilt == [(source_handle, CodexAdvisoryStage.REPORT_DRAFT)]
    return result


def test_report_draft_projects_bounded_untrusted_notes_without_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _verified_input()
    payload = _draft_payload(source)
    payload["overview"] = "Check *severity* and [source](https://example.invalid)."
    notes = payload["findingNotes"]
    assert isinstance(notes, list)
    notes[0]["note"] = "A `draft` note with <script>alert(1)</script>."

    projection = _admit(monkeypatch, payload, source=source)

    assert projection.input_digest == source.input_digest
    assert projection.promotion_digest == source.promotion_digest
    assert projection.markdown_sha256 == sha256(projection.markdown.encode()).hexdigest()
    assert projection.model_origin_verified is False
    assert projection.finding_authorized is False
    assert projection.graph_write_authorized is False
    assert projection.report_delivery_authorized is False
    assert "Model origin and prose accuracy are unverified" in projection.markdown
    assert "This is not the canonical PAJIN report" in projection.markdown
    assert "\\*severity\\*" in projection.markdown
    assert "\\[source\\]" in projection.markdown
    assert "&lt;script&gt;" in projection.markdown
    assert "`draft`" not in projection.markdown
    assert tuple(signal.finding_ref for signal in source.finding_signals) == tuple(
        note.finding_ref for note in projection.draft.finding_notes
    )
    assert projection.markdown.count("Verified severity:") == 3

    with pytest.raises(ValueError):
        replace(projection, finding_authorized=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        replace(projection, markdown=projection.markdown + "unsealed change")


@pytest.mark.parametrize(
    "change",
    [
        lambda raw: raw.update({"inputDigest": "0" * 64}),
        lambda raw: raw.update({"targetUrl": "https://example.invalid/private"}),
        lambda raw: raw.update({"findingAuthorized": True}),
        lambda raw: raw.update({"findingAuthorized": 0}),
        lambda raw: raw.update({"reportDeliveryAuthorized": True}),
        lambda raw: raw.update({"modelOriginVerified": True}),
        lambda raw: raw.update({"stage": "vulnerability-analysis"}),
        lambda raw: raw["findingNotes"].pop(),
        lambda raw: raw["findingNotes"].append(raw["findingNotes"][0]),
        lambda raw: raw["findingNotes"].reverse(),
        lambda raw: raw["findingNotes"][0].update({"findingRef": "csf_" + "e" * 32}),
        lambda raw: raw.update({"overview": "First line\nSecond line"}),
        lambda raw: raw.update({"overview": "\u202eHidden order"}),
        lambda raw: raw.update({"overview": "a" * 701}),
    ],
)
def test_report_draft_rejects_foreign_authority_or_unbounded_content(
    monkeypatch: pytest.MonkeyPatch,
    change: object,
) -> None:
    source = _verified_input()
    payload = _draft_payload(source)
    assert callable(change)
    change(payload)
    with pytest.raises(report_draft.CodexSolReportDraftError):
        _admit(monkeypatch, payload, source=source)


@pytest.mark.parametrize(
    "content",
    [
        b'{"inputDigest":"a","inputDigest":"b"}',
        b"[]",
        b"{",
        b"x" * (16 * 1024 + 1),
    ],
)
def test_report_draft_rejects_ambiguous_or_oversized_json(
    monkeypatch: pytest.MonkeyPatch,
    content: bytes,
) -> None:
    with pytest.raises(report_draft.CodexSolReportDraftError):
        _admit(monkeypatch, content)


def test_report_draft_requires_independent_input_digest_and_real_strict_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _verified_input()
    payload = _draft_payload(source)
    with pytest.raises(report_draft.CodexSolReportDraftError):
        _admit(monkeypatch, payload, source=source, expected_input_digest="f" * 64)

    # Without the test-only input builder, an arbitrary object cannot impersonate
    # a strictly reloaded completed governed Campaign.
    monkeypatch.undo()
    with pytest.raises(report_draft.CodexSolReportDraftError):
        report_draft.admit_codex_sol_report_draft(
            cast(VerifiedGovernedWebCompletedCampaign, object()),
            _encoded(payload),
            expected_input_digest=source.input_digest,
        )
