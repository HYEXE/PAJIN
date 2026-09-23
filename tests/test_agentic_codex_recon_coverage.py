"""Coverage remains complete as an inventory, bounded as evidence, and inert."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import ValidationError

import pajin.agentic.codex_recon_coverage as coverage_module
from pajin.agentic.codex_recon_coverage import (
    CodexReconCoverage,
    build_codex_recon_coverage,
)
from pajin.agentic.codex_recon_draft import CodexReconDraft
from pajin.agentic.codex_recon_projection import CodexReconProjection
from pajin.capabilities.web_browser_assessment import WEB_BROWSER_ASSESSMENT_ORIGIN
from pajin.discovery.canonicalization import discovery_digest
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun

_RUN_ID = "run_20260915T020000Z_a1b2c3d4"
_ROOT = "a" * 64
_PLAN = "b" * 64
_RESULT = "c" * 64
_PROJECTION = "d" * 64


def _stub_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    origin: str = WEB_BROWSER_ASSESSMENT_ORIGIN,
) -> tuple[VerifiedAuthenticatedDiscoveryRun, list[str]]:
    source = object.__new__(VerifiedAuthenticatedDiscoveryRun)
    object.__setattr__(source, "run_path", tmp_path / "sealed-source")
    calls: list[str] = []
    reloaded = SimpleNamespace(
        plan=SimpleNamespace(origin=origin, plan_digest=_PLAN),
        discovery=SimpleNamespace(
            discovery_plan=SimpleNamespace(max_routes=4, max_depth=1),
            discovery_result=SimpleNamespace(result_digest=_RESULT),
        ),
    )

    def strict_reload(
        path: Path, *, expected_run_id: str, expected_root_digest: str
    ) -> SimpleNamespace:
        assert path == source.run_path
        assert (expected_run_id, expected_root_digest) == (_RUN_ID, _ROOT)
        calls.append("strict-reload")
        return reloaded

    def project(
        loaded: object, *, expected_run_id: str, expected_root_digest: str
    ) -> SimpleNamespace:
        assert loaded is reloaded
        assert (expected_run_id, expected_root_digest) == (_RUN_ID, _ROOT)
        calls.append("project")
        return SimpleNamespace(projection_digest=_PROJECTION)

    monkeypatch.setattr(coverage_module, "load_verified_authenticated_discovery", strict_reload)
    monkeypatch.setattr(coverage_module, "build_codex_recon_projection", project)
    return source, calls


def test_loopback_coverage_includes_all_tracks_without_execution_rank(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, calls = _stub_source(tmp_path, monkeypatch)
    review = build_codex_recon_coverage(source, expected_run_id=_RUN_ID, expected_root_digest=_ROOT)

    assert calls == ["strict-reload", "project"]
    assert {track.track_id: track.status for track in review.tracks} == {
        "active-surface-enumeration": "not-assessed",
        "asset-identification": "scope-bound",
        "bounded-web-surface": "observed-bounded",
        "diagnostic-hypotheses": "not-assessed",
        "entry-point-inventory": "observed-bounded",
        "passive-web-surface": "not-assessed",
        "public-osint": "not-applicable",
        "technology-fingerprint": "not-assessed",
        "workflow-map": "not-assessed",
    }
    assert review.exhaustive_coverage is False
    assert review.diagnostic_rank_is_execution_order is False
    assert review.external_asset_scope_authorized is False
    assert review.external_lookup_authorized is False
    assert review.target_action_authorized is False
    assert "rank" not in review.model_dump_json(by_alias=True)
    assert CodexReconCoverage.model_validate_json(review.model_dump_json(by_alias=True)) == review


def test_forged_coverage_cannot_mark_unassessed_track_observed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = _stub_source(tmp_path, monkeypatch)
    review = build_codex_recon_coverage(source, expected_run_id=_RUN_ID, expected_root_digest=_ROOT)
    forged = review.model_dump(mode="json", by_alias=True)
    forged["tracks"][0]["status"] = "observed-bounded"
    forged["tracks"][0]["evidenceDigest"] = _RESULT
    forged["coverageDigest"] = discovery_digest(
        "pajin.codex-recon-coverage/v1alpha1",
        {key: value for key, value in forged.items() if key != "coverageDigest"},
    )
    with pytest.raises(ValidationError, match="overstates"):
        CodexReconCoverage.model_validate(forged)


def test_external_origin_is_not_silently_added_to_local_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, calls = _stub_source(tmp_path, monkeypatch, origin="https://example.invalid")
    with pytest.raises(ValueError, match="outside the exact loopback lab"):
        build_codex_recon_coverage(source, expected_run_id=_RUN_ID, expected_root_digest=_ROOT)
    assert calls == ["strict-reload"]


def test_existing_draft_is_only_a_proposal_track(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = _stub_source(tmp_path, monkeypatch)
    draft = CodexReconDraft.model_validate(
        {
            "apiVersion": "pajin.dev/codex-recon-draft/v1alpha1",
            "kind": "CodexReconDraft",
            "projectionDigest": _PROJECTION,
            "prioritizedDiagnostics": [
                {
                    "rank": rank,
                    "diagnosticId": diagnostic,
                    "catalogEntryId": entry,
                    "hypothesisId": hypothesis,
                    "evidenceRefs": ["wae_" + "e" * 32],
                }
                for rank, diagnostic, entry, hypothesis in (
                    (
                        1,
                        "sql-login",
                        "pajin.web-analysis.diagnostic.sql-login.v1",
                        "pajin.web-analysis.hypothesis.sql-login-authentication-bypass.v1",
                    ),
                    (
                        2,
                        "object-access",
                        "pajin.web-analysis.diagnostic.object-access.v1",
                        "pajin.web-analysis.hypothesis.cross-account-object-access.v1",
                    ),
                    (
                        3,
                        "dom-xss",
                        "pajin.web-analysis.diagnostic.dom-xss.v1",
                        "pajin.web-analysis.hypothesis.client-marker-execution.v1",
                    ),
                )
            ],
            "pathAssessments": [
                {
                    "catalogEntryId": entry,
                    "hypothesisId": hypothesis,
                    "issueSequence": issues,
                    "disposition": "investigate",
                    "evidenceRefs": ["wae_" + "e" * 32],
                }
                for entry, hypothesis, issues in (
                    (
                        "pajin.web-analysis.path.sql-login-object-access.v1",
                        "pajin.web-analysis.hypothesis.authentication-to-object-access.v1",
                        ["sql-login", "object-access"],
                    ),
                    (
                        "pajin.web-analysis.path.dom-xss.v1",
                        "pajin.web-analysis.hypothesis.client-marker-impact.v1",
                        ["dom-xss"],
                    ),
                )
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

    def admit(content: bytes, *, expected_projection: CodexReconProjection) -> CodexReconDraft:
        assert content == draft.model_dump_json(by_alias=True).encode()
        assert expected_projection.projection_digest == _PROJECTION
        return draft

    monkeypatch.setattr(coverage_module, "parse_codex_recon_draft", admit)
    review = build_codex_recon_coverage(
        source,
        expected_run_id=_RUN_ID,
        expected_root_digest=_ROOT,
        draft=draft,
    )
    hypotheses = next(track for track in review.tracks if track.track_id == "diagnostic-hypotheses")
    assert hypotheses.status == "proposal-only"
    assert hypotheses.evidence_digest == review.draft_digest
    assert review.tracks[0].status == "not-assessed"
    assert review.target_action_authorized is False


def test_unverified_source_object_is_rejected_before_reload() -> None:
    with pytest.raises(ValueError, match="exact verified source"):
        build_codex_recon_coverage(
            cast(VerifiedAuthenticatedDiscoveryRun, object()),
            expected_run_id=_RUN_ID,
            expected_root_digest=_ROOT,
        )
