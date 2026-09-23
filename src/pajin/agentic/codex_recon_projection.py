"""Target-neutral hosted-recon projection from a strictly reloaded Web source.

Constructing this projection is local-only and confers no hosted-transfer authority.
"""

from __future__ import annotations

from typing import Final, Literal, Self

from pydantic import Field, model_validator

from pajin.agentic.codex_routing import CodexAdvisoryWireModel
from pajin.discovery.canonicalization import discovery_digest
from pajin.web_assessment.analysis_proposal import (
    WebAnalysisEvidenceSignal,
    WebAnalysisProjectionDiagnostic,
    WebAnalysisProjectionPath,
    build_web_analysis_snapshot,
)
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun

CODEX_RECON_PROJECTION_API_VERSION: Final = "pajin.dev/codex-recon-projection/v1alpha1"
_RECON_DIGEST_DOMAIN: Final = "pajin.codex-recon-projection/v1alpha1"


class CodexReconProjection(CodexAdvisoryWireModel):
    """Only bounded catalog entries, bucketed signals, and opaque references."""

    api_version: Literal["pajin.dev/codex-recon-projection/v1alpha1"] = Field(alias="apiVersion")
    kind: Literal["CodexReconProjection"]
    diagnostics: tuple[
        WebAnalysisProjectionDiagnostic,
        WebAnalysisProjectionDiagnostic,
        WebAnalysisProjectionDiagnostic,
    ] = Field(strict=False)
    attack_paths: tuple[WebAnalysisProjectionPath, WebAnalysisProjectionPath] = Field(
        alias="attackPaths", strict=False
    )
    evidence_signals: tuple[WebAnalysisEvidenceSignal, ...] = Field(
        alias="evidenceSignals", min_length=1, max_length=16, strict=False
    )
    source_anchors_embedded: Literal[False] = Field(alias="sourceAnchorsEmbedded")
    target_content_embedded: Literal[False] = Field(alias="targetContentEmbedded")
    tool_access_authorized: Literal[False] = Field(alias="toolAccessAuthorized")
    execution_authorized: Literal[False] = Field(alias="executionAuthorized")
    finding_authorized: Literal[False] = Field(alias="findingAuthorized")
    publication_authorized: Literal[False] = Field(alias="publicationAuthorized")
    projection_digest: str = Field(alias="projectionDigest", pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def require_code_owned_recon_projection(self) -> Self:
        if tuple(item.diagnostic_id for item in self.diagnostics) != (
            "sql-login",
            "object-access",
            "dom-xss",
        ):
            raise ValueError("Hosted recon projection differs from code-owned diagnostic order")
        if tuple(item.issue_sequence for item in self.attack_paths) != (
            ("sql-login", "object-access"),
            ("dom-xss",),
        ):
            raise ValueError("Hosted recon projection differs from code-owned path order")
        refs = tuple(item.evidence_ref for item in self.evidence_signals)
        if refs != tuple(sorted(set(refs))):
            raise ValueError("Hosted recon projection Evidence references differ")
        if self.projection_digest != discovery_digest(
            _RECON_DIGEST_DOMAIN,
            self.model_dump(mode="json", by_alias=True, exclude={"projection_digest"}),
        ):
            raise ValueError("Hosted recon projection digest differs from its content")
        return self


def build_codex_recon_projection(
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    expected_run_id: str,
    expected_root_digest: str,
) -> CodexReconProjection:
    """Reload the sealed source and project only its existing safe model view."""

    snapshot = build_web_analysis_snapshot(
        source,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
    )
    local_projection = snapshot.model_projection
    payload = {
        "apiVersion": CODEX_RECON_PROJECTION_API_VERSION,
        "kind": "CodexReconProjection",
        "diagnostics": [
            item.model_dump(mode="json", by_alias=True) for item in local_projection.diagnostics
        ],
        "attackPaths": [
            item.model_dump(mode="json", by_alias=True) for item in local_projection.attack_paths
        ],
        "evidenceSignals": [
            item.model_dump(mode="json", by_alias=True)
            for item in local_projection.evidence_signals
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
            "projectionDigest": discovery_digest(_RECON_DIGEST_DOMAIN, payload),
        }
    )
