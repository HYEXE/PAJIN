"""Local-only reconnaissance coverage review for one sealed loopback source.

The fixed track order is canonical serialization, never diagnostic or execution order.
External assets need a separate scope and evidence contract before any collection.
"""

from __future__ import annotations

from typing import Final, Literal, Self

from pydantic import Field, model_validator

from pajin.agentic.codex_recon_draft import CodexReconDraft, parse_codex_recon_draft
from pajin.agentic.codex_recon_projection import build_codex_recon_projection
from pajin.agentic.codex_routing import CodexAdvisoryWireModel
from pajin.capabilities.web_browser_assessment import WEB_BROWSER_ASSESSMENT_ORIGIN
from pajin.discovery.canonicalization import discovery_digest
from pajin.web_assessment.discovery_artifact import (
    VerifiedAuthenticatedDiscoveryRun,
    load_verified_authenticated_discovery,
)

CODEX_RECON_COVERAGE_API_VERSION: Final = "pajin.dev/codex-recon-coverage/v1alpha1"
_COVERAGE_DOMAIN: Final = "pajin.codex-recon-coverage/v1alpha1"
_DRAFT_DOMAIN: Final = "pajin.codex-recon-admitted-draft/v1alpha1"

ReconTrackId = Literal[
    "active-surface-enumeration",
    "asset-identification",
    "bounded-web-surface",
    "diagnostic-hypotheses",
    "entry-point-inventory",
    "passive-web-surface",
    "public-osint",
    "technology-fingerprint",
    "workflow-map",
]
ReconTrackStatus = Literal[
    "not-applicable", "not-assessed", "observed-bounded", "proposal-only", "scope-bound"
]
_TRACK_IDS: Final[tuple[ReconTrackId, ...]] = (
    "active-surface-enumeration",
    "asset-identification",
    "bounded-web-surface",
    "diagnostic-hypotheses",
    "entry-point-inventory",
    "passive-web-surface",
    "public-osint",
    "technology-fingerprint",
    "workflow-map",
)


class CodexReconCoverageTrack(CodexAdvisoryWireModel):
    track_id: ReconTrackId = Field(alias="trackId")
    status: ReconTrackStatus
    evidence_digest: str | None = Field(alias="evidenceDigest", pattern=r"^[a-f0-9]{64}$")


class CodexReconCoverage(CodexAdvisoryWireModel):
    """Record every track without treating a model rank as coverage or authority."""

    api_version: Literal["pajin.dev/codex-recon-coverage/v1alpha1"] = Field(alias="apiVersion")
    kind: Literal["CodexReconCoverage"]
    coverage_digest: str = Field(alias="coverageDigest", pattern=r"^[a-f0-9]{64}$")
    scope_kind: Literal["exact-loopback-lab"] = Field(alias="scopeKind")
    source_run_id: str = Field(alias="sourceRunId", pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=r"^[a-f0-9]{64}$")
    source_plan_digest: str = Field(alias="sourcePlanDigest", pattern=r"^[a-f0-9]{64}$")
    discovery_result_digest: str = Field(alias="discoveryResultDigest", pattern=r"^[a-f0-9]{64}$")
    projection_digest: str = Field(alias="projectionDigest", pattern=r"^[a-f0-9]{64}$")
    draft_digest: str | None = Field(alias="draftDigest", pattern=r"^[a-f0-9]{64}$")
    max_routes: Literal[4] = Field(alias="maxRoutes")
    max_depth: Literal[1] = Field(alias="maxDepth")
    tracks: tuple[CodexReconCoverageTrack, ...] = Field(min_length=9, max_length=9, strict=False)
    exhaustive_coverage: Literal[False] = Field(alias="exhaustiveCoverage")
    diagnostic_rank_is_execution_order: Literal[False] = Field(
        alias="diagnosticRankIsExecutionOrder"
    )
    external_asset_scope_authorized: Literal[False] = Field(alias="externalAssetScopeAuthorized")
    external_lookup_authorized: Literal[False] = Field(alias="externalLookupAuthorized")
    target_action_authorized: Literal[False] = Field(alias="targetActionAuthorized")
    hosted_transfer_authorized: Literal[False] = Field(alias="hostedTransferAuthorized")
    finding_authorized: Literal[False] = Field(alias="findingAuthorized")

    @model_validator(mode="after")
    def bind_bounded_review(self) -> Self:
        if tuple(track.track_id for track in self.tracks) != _TRACK_IDS:
            raise ValueError("Recon coverage must record every code-owned track once")
        expected: tuple[tuple[ReconTrackStatus, str | None], ...] = (
            ("not-assessed", None),
            ("scope-bound", self.source_plan_digest),
            ("observed-bounded", self.discovery_result_digest),
            (
                "proposal-only" if self.draft_digest is not None else "not-assessed",
                self.draft_digest,
            ),
            ("observed-bounded", self.discovery_result_digest),
            ("not-assessed", None),
            ("not-applicable", None),
            ("not-assessed", None),
            ("not-assessed", None),
        )
        if tuple((track.status, track.evidence_digest) for track in self.tracks) != expected:
            raise ValueError("Recon coverage overstates the sealed loopback observations")
        material = self.model_dump(mode="json", by_alias=True, exclude={"coverage_digest"})
        if self.coverage_digest != discovery_digest(_COVERAGE_DOMAIN, material):
            raise ValueError("Recon coverage digest differs from its content")
        return self


def build_codex_recon_coverage(
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    expected_run_id: str,
    expected_root_digest: str,
    draft: CodexReconDraft | None = None,
) -> CodexReconCoverage:
    """Strictly reload the local source and mark unobserved work explicitly."""

    if type(source) is not VerifiedAuthenticatedDiscoveryRun:
        raise ValueError("Recon coverage requires an exact verified source")
    current = load_verified_authenticated_discovery(
        source.run_path,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
    )
    if current.plan.origin != WEB_BROWSER_ASSESSMENT_ORIGIN:
        raise ValueError("Recon coverage source is outside the exact loopback lab")
    projection = build_codex_recon_projection(
        current,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
    )
    draft_digest: str | None = None
    if draft is not None:
        if type(draft) is not CodexReconDraft:
            raise ValueError("Recon coverage draft must be an exact admitted model")
        admitted = parse_codex_recon_draft(
            draft.model_dump_json(by_alias=True).encode(), expected_projection=projection
        )
        draft_digest = discovery_digest(
            _DRAFT_DOMAIN, admitted.model_dump(mode="json", by_alias=True)
        )
    result = current.discovery.discovery_result
    plan = current.discovery.discovery_plan
    if plan.max_routes != 4 or plan.max_depth != 1:
        raise ValueError("Recon coverage differs from the bounded loopback discovery plan")
    entries: tuple[tuple[ReconTrackStatus, str | None], ...] = (
        ("not-assessed", None),
        ("scope-bound", current.plan.plan_digest),
        ("observed-bounded", result.result_digest),
        ("proposal-only" if draft_digest is not None else "not-assessed", draft_digest),
        ("observed-bounded", result.result_digest),
        ("not-assessed", None),
        ("not-applicable", None),
        ("not-assessed", None),
        ("not-assessed", None),
    )
    payload = {
        "apiVersion": CODEX_RECON_COVERAGE_API_VERSION,
        "kind": "CodexReconCoverage",
        "scopeKind": "exact-loopback-lab",
        "sourceRunId": expected_run_id,
        "sourceRootDigest": expected_root_digest,
        "sourcePlanDigest": current.plan.plan_digest,
        "discoveryResultDigest": result.result_digest,
        "projectionDigest": projection.projection_digest,
        "draftDigest": draft_digest,
        "maxRoutes": plan.max_routes,
        "maxDepth": plan.max_depth,
        "tracks": [
            {"trackId": track_id, "status": status, "evidenceDigest": digest}
            for track_id, (status, digest) in zip(_TRACK_IDS, entries, strict=True)
        ],
        "exhaustiveCoverage": False,
        "diagnosticRankIsExecutionOrder": False,
        "externalAssetScopeAuthorized": False,
        "externalLookupAuthorized": False,
        "targetActionAuthorized": False,
        "hostedTransferAuthorized": False,
        "findingAuthorized": False,
    }
    return CodexReconCoverage.model_validate(
        {**payload, "coverageDigest": discovery_digest(_COVERAGE_DOMAIN, payload)}
    )
