"""Proposal-only LLM analysis contracts for one sealed local Web assessment.

The local snapshot in this module binds a verified WEB source Run to the current
production adapter and diagnostic catalogs.  Only ``model_projection`` is safe to
send to a Provider.  The projection deliberately contains no target text, origin,
route, form, selector, request identity, or source digest.  Model output remains an
inert prioritisation proposal and cannot construct tools, capabilities, permits,
execution, Graph admission, Findings, reports, PoCs, or delivery.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Mapping, Sequence
from datetime import UTC
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Final, Literal, Protocol, Self, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import RunIntegrityVerification
from pajin.web_assessment.diagnostic_catalog import (
    DiagnosticBundleDescriptor,
    production_diagnostic_bundle_catalog,
)
from pajin.web_assessment.discovery import browser_discovery_request_path_rejection
from pajin.web_assessment.discovery_artifact import (
    AuthenticatedDiscoveryRunIndex,
    VerifiedAuthenticatedDiscoveryRun,
    code_owned_authenticated_discovery_plan,
    load_verified_authenticated_discovery,
)
from pajin.web_assessment.discovery_evidence import AuthenticatedDiscoveryEvidence
from pajin.web_assessment.governed_adapter_profile import (
    ResolvedGovernedWebAdapterProfile,
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.models import LocalWebAssessmentAuthorization, WebAssessmentPlan

WEB_ANALYSIS_SNAPSHOT_API_VERSION: Final = "pajin.dev/web-analysis-snapshot/v1alpha1"
WEB_ANALYSIS_MODEL_PROJECTION_API_VERSION: Final = (
    "pajin.dev/web-analysis-model-projection/v1alpha1"
)
WEB_ANALYSIS_PROPOSAL_DRAFT_API_VERSION: Final = "pajin.dev/web-analysis-proposal-draft/v1alpha1"
COMPILED_WEB_ANALYSIS_PROPOSAL_API_VERSION: Final = (
    "pajin.dev/compiled-web-analysis-proposal/v1alpha1"
)
WEB_ANALYSIS_COMPILATION_POLICY_API_VERSION: Final = (
    "pajin.dev/web-analysis-compilation-policy/v1alpha1"
)

_MAX_COMPONENT_BYTES = 256 * 1024
_MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
_MAX_DRAFT_BYTES = 128 * 1024
_MAX_PROPOSAL_BYTES = 2 * 1024 * 1024
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_EVIDENCE_REF_RE = re.compile(r"^wae_[a-f0-9]{32}$")
_RUN_ID_RE = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")

DiagnosticId = Literal["sql-login", "object-access", "dom-xss"]
PathDisposition = Literal["investigate", "insufficient-evidence"]
CountBucket = Literal["zero", "one", "two-to-five", "six-to-twenty", "over-twenty"]
SignalKind = Literal[
    "discovered-route-count",
    "discovered-form-count",
    "discovered-control-count",
    "passive-request-count",
]
EvidenceSourceKind = Literal[
    "discovery-route-set",
    "discovery-form-set",
    "discovery-control-set",
    "passive-request-set",
]

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_EvidenceRef = Annotated[str, Field(pattern=r"^wae_[a-f0-9]{32}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]

_DIAGNOSTIC_CATALOG_ENTRIES: Final[Mapping[DiagnosticId, tuple[str, str]]] = {
    "sql-login": (
        "pajin.web-analysis.diagnostic.sql-login.v1",
        "pajin.web-analysis.hypothesis.sql-login-authentication-bypass.v1",
    ),
    "object-access": (
        "pajin.web-analysis.diagnostic.object-access.v1",
        "pajin.web-analysis.hypothesis.cross-account-object-access.v1",
    ),
    "dom-xss": (
        "pajin.web-analysis.diagnostic.dom-xss.v1",
        "pajin.web-analysis.hypothesis.client-marker-execution.v1",
    ),
}
_PATH_CATALOG_ENTRIES: Final[Mapping[tuple[DiagnosticId, ...], tuple[str, str]]] = {
    ("sql-login", "object-access"): (
        "pajin.web-analysis.path.sql-login-object-access.v1",
        "pajin.web-analysis.hypothesis.authentication-to-object-access.v1",
    ),
    ("dom-xss",): (
        "pajin.web-analysis.path.dom-xss.v1",
        "pajin.web-analysis.hypothesis.client-marker-impact.v1",
    ),
}

_FORBIDDEN_STRUCTURAL_KEYS: Final = frozenset(
    {
        "url",
        "origin",
        "route",
        "selector",
        "method",
        "header",
        "headers",
        "payload",
        "javascript",
        "script",
        "js",
        "prompt",
        "message",
        "messages",
        "argument",
        "arguments",
        "command",
        "argv",
        "shell",
        "target",
        "scope",
        "tool",
        "toolrequest",
        "capability",
        "capabilitygrant",
        "permit",
        "actionpermit",
    }
)


class WebAnalysisProposalError(ValueError):
    """Raised when analysis proposal construction or verification fails closed."""


class _VerifiedSourceLoader(Protocol):
    """Reload one exact sealed source Run from independently supplied anchors."""

    def __call__(
        self,
        run_path: Path,
        *,
        expected_run_id: str,
        expected_root_digest: str,
    ) -> VerifiedAuthenticatedDiscoveryRun: ...


class _AliasWireModel(BaseModel):
    """Frozen alias-only wire model; Python field spellings are never accepted."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Web analysis authority marker must be literal boolean false")
    return False


def _canonical_refs(value: Sequence[str], *, label: str) -> tuple[str, ...]:
    refs = tuple(value)
    if not refs or refs != tuple(sorted(set(refs))):
        raise ValueError(f"{label} must be non-empty, unique, and sorted")
    if any(_EVIDENCE_REF_RE.fullmatch(ref) is None for ref in refs):
        raise ValueError(f"{label} contains an invalid opaque Evidence reference")
    return refs


class WebAnalysisProjectionDiagnostic(_AliasWireModel):
    """One code-owned diagnostic option exposed without executable recipe material."""

    diagnostic_id: DiagnosticId = Field(alias="diagnosticId")
    catalog_entry_id: _Identifier = Field(alias="catalogEntryId")
    allowed_hypothesis_ids: tuple[_Identifier, ...] = Field(
        alias="allowedHypothesisIds",
        min_length=1,
        max_length=4,
    )

    @model_validator(mode="after")
    def bind_code_owned_entry(self) -> Self:
        entry, hypothesis = _DIAGNOSTIC_CATALOG_ENTRIES[self.diagnostic_id]
        if self.catalog_entry_id != entry or self.allowed_hypothesis_ids != (hypothesis,):
            raise ValueError("Web analysis diagnostic projection differs from code authority")
        return self


class WebAnalysisProjectionPath(_AliasWireModel):
    """One code-owned attack-path shape exposed without target-specific narrative."""

    catalog_entry_id: _Identifier = Field(alias="catalogEntryId")
    issue_sequence: tuple[DiagnosticId, ...] = Field(
        alias="issueSequence",
        min_length=1,
        max_length=3,
    )
    allowed_hypothesis_ids: tuple[_Identifier, ...] = Field(
        alias="allowedHypothesisIds",
        min_length=1,
        max_length=4,
    )
    allowed_dispositions: tuple[PathDisposition, PathDisposition] = Field(
        alias="allowedDispositions"
    )

    @model_validator(mode="after")
    def bind_code_owned_entry(self) -> Self:
        expected = _PATH_CATALOG_ENTRIES.get(self.issue_sequence)
        if (
            expected is None
            or self.catalog_entry_id != expected[0]
            or self.allowed_hypothesis_ids != (expected[1],)
            or self.allowed_dispositions != ("investigate", "insufficient-evidence")
        ):
            raise ValueError("Web analysis path projection differs from code authority")
        return self


class WebAnalysisEvidenceSignal(_AliasWireModel):
    """Provider-safe signal: opaque reference plus code-owned enums and a count bucket."""

    evidence_ref: _EvidenceRef = Field(alias="evidenceRef")
    signal_kind: SignalKind = Field(alias="signalKind")
    count_bucket: CountBucket = Field(alias="countBucket")
    supports_catalog_entries: tuple[_Identifier, ...] = Field(
        alias="supportsCatalogEntries",
        min_length=1,
        max_length=5,
    )

    @field_validator("supports_catalog_entries")
    @classmethod
    def require_canonical_entries(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("Web analysis supported catalog entries must be unique and sorted")
        if any(entry not in _ALL_CATALOG_ENTRY_IDS for entry in value):
            raise ValueError("Web analysis signal names an unknown catalog entry")
        return value


class WebAnalysisModelProjection(_AliasWireModel):
    """The only Web-analysis object allowed in a Provider request."""

    api_version: Literal["pajin.dev/web-analysis-model-projection/v1alpha1"] = Field(
        alias="apiVersion"
    )
    kind: Literal["WebAnalysisModelProjection"]
    projection_id: str = Field(alias="projectionId", max_length=110)
    projection_digest: str = Field(alias="projectionDigest", max_length=64)
    diagnostics: tuple[
        WebAnalysisProjectionDiagnostic,
        WebAnalysisProjectionDiagnostic,
        WebAnalysisProjectionDiagnostic,
    ]
    attack_paths: tuple[WebAnalysisProjectionPath, WebAnalysisProjectionPath] = Field(
        alias="attackPaths"
    )
    evidence_signals: tuple[WebAnalysisEvidenceSignal, ...] = Field(
        alias="evidenceSignals",
        min_length=1,
        max_length=16,
    )
    projection_state: Literal["opaque-proposal-input-not-authority"] = Field(
        alias="projectionState"
    )
    source_anchors_embedded: Literal[False] = Field(alias="sourceAnchorsEmbedded")
    target_content_embedded: Literal[False] = Field(alias="targetContentEmbedded")
    raw_evidence_embedded: Literal[False] = Field(alias="rawEvidenceEmbedded")
    instruction_authorized: Literal[False] = Field(alias="instructionAuthorized")
    tool_access_authorized: Literal[False] = Field(alias="toolAccessAuthorized")
    capability_granted: Literal[False] = Field(alias="capabilityGranted")
    permit_granted: Literal[False] = Field(alias="permitGranted")
    execution_authorized: Literal[False] = Field(alias="executionAuthorized")

    @field_validator(
        "source_anchors_embedded",
        "target_content_embedded",
        "raw_evidence_embedded",
        "instruction_authorized",
        "tool_access_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_projection(self) -> Self:
        expected_diagnostics = tuple(_DIAGNOSTIC_CATALOG_ENTRIES)
        if tuple(item.diagnostic_id for item in self.diagnostics) != expected_diagnostics:
            raise ValueError("Web analysis projection requires the exact diagnostic catalog order")
        expected_paths = tuple(_PATH_CATALOG_ENTRIES)
        if tuple(item.issue_sequence for item in self.attack_paths) != expected_paths:
            raise ValueError("Web analysis projection requires the exact attack-path catalog order")
        refs = tuple(item.evidence_ref for item in self.evidence_signals)
        if refs != tuple(sorted(set(refs))):
            raise ValueError(
                "Web analysis projection Evidence references must be unique and sorted"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"projection_id", "projection_digest"},
        )
        digest = _digest("pajin.web-analysis.model-projection/v1", material)
        projection_id = f"web-analysis-projection:{digest}"
        if self.projection_digest and self.projection_digest != digest:
            raise ValueError("Web analysis Model Projection Digest differs")
        if self.projection_id and self.projection_id != projection_id:
            raise ValueError("Web analysis Model Projection ID differs")
        object.__setattr__(self, "projection_digest", digest)
        object.__setattr__(self, "projection_id", projection_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Web analysis model projection",
            max_bytes=_MAX_COMPONENT_BYTES,
        )
        return self


class WebAnalysisEvidenceBinding(_AliasWireModel):
    """Local-only resolution of one opaque Provider reference to sealed source evidence."""

    evidence_ref: _EvidenceRef = Field(alias="evidenceRef")
    source_kind: EvidenceSourceKind = Field(alias="sourceKind")
    source_identifier: str = Field(alias="sourceIdentifier", min_length=1, max_length=200)
    source_digest: _Sha256 = Field(alias="sourceDigest")
    signal_kind: SignalKind = Field(alias="signalKind")
    count_bucket: CountBucket = Field(alias="countBucket")
    supports_catalog_entries: tuple[_Identifier, ...] = Field(
        alias="supportsCatalogEntries",
        min_length=1,
        max_length=5,
    )

    @field_validator("supports_catalog_entries")
    @classmethod
    def require_canonical_entries(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("Web analysis binding catalog entries must be unique and sorted")
        if any(entry not in _ALL_CATALOG_ENTRY_IDS for entry in value):
            raise ValueError("Web analysis binding names an unknown catalog entry")
        return value

    def model_signal(self) -> WebAnalysisEvidenceSignal:
        """Return a detached Provider-safe projection of this local binding."""

        return WebAnalysisEvidenceSignal(
            evidenceRef=self.evidence_ref,
            signalKind=self.signal_kind,
            countBucket=self.count_bucket,
            supportsCatalogEntries=self.supports_catalog_entries,
        )


class WebAnalysisSnapshot(_AliasWireModel):
    """Local secret-free binding of sealed evidence to one Provider-safe projection."""

    api_version: Literal["pajin.dev/web-analysis-snapshot/v1alpha1"] = Field(alias="apiVersion")
    kind: Literal["WebAnalysisSnapshot"]
    snapshot_id: str = Field(alias="snapshotId", max_length=110)
    snapshot_digest: str = Field(alias="snapshotDigest", max_length=64)
    source_run_id: str = Field(alias="sourceRunId", pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_index_digest: _Sha256 = Field(alias="sourceIndexDigest")
    source_plan_digest: _Sha256 = Field(alias="sourcePlanDigest")
    source_discovery_evidence_digest: _Sha256 = Field(alias="sourceDiscoveryEvidenceDigest")
    source_discovery_plan_digest: _Sha256 = Field(alias="sourceDiscoveryPlanDigest")
    source_discovery_result_digest: _Sha256 = Field(alias="sourceDiscoveryResultDigest")
    profile_registry_digest: _Sha256 = Field(alias="profileRegistryDigest")
    profile_digest: _Sha256 = Field(alias="profileDigest")
    adapter_catalog_digest: _Sha256 = Field(alias="adapterCatalogDigest")
    diagnostic_catalog_digest: _Sha256 = Field(alias="diagnosticCatalogDigest")
    diagnostic_bundle_id: _Identifier = Field(alias="diagnosticBundleId")
    diagnostic_bundle_digest: _Sha256 = Field(alias="diagnosticBundleDigest")
    adapter_implementation_id: _Identifier = Field(alias="adapterImplementationId")
    adapter_implementation_digest: _Sha256 = Field(alias="adapterImplementationDigest")
    executor_id: _Identifier = Field(alias="executorId")
    executor_implementation_digest: _Sha256 = Field(alias="executorImplementationDigest")
    path_builder_id: _Identifier = Field(alias="pathBuilderId")
    path_builder_implementation_digest: _Sha256 = Field(alias="pathBuilderImplementationDigest")
    evidence_bindings: tuple[WebAnalysisEvidenceBinding, ...] = Field(
        alias="evidenceBindings",
        min_length=1,
        max_length=16,
    )
    model_projection: WebAnalysisModelProjection = Field(alias="modelProjection")
    snapshot_state: Literal["sealed-source-bound-proposal-only"] = Field(alias="snapshotState")
    secret_material_embedded: Literal[False] = Field(alias="secretMaterialEmbedded")
    target_content_model_visible: Literal[False] = Field(alias="targetContentModelVisible")
    scope_expansion_authority: Literal[False] = Field(alias="scopeExpansionAuthority")
    tool_request_authority: Literal[False] = Field(alias="toolRequestAuthority")
    capability_authority: Literal[False] = Field(alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(alias="permitAuthority")
    execution_authority: Literal[False] = Field(alias="executionAuthority")
    graph_admission_authority: Literal[False] = Field(alias="graphAdmissionAuthority")
    finding_authority: Literal[False] = Field(alias="findingAuthority")
    report_delivery_authority: Literal[False] = Field(alias="reportDeliveryAuthority")

    @field_validator(
        "secret_material_embedded",
        "target_content_model_visible",
        "scope_expansion_authority",
        "tool_request_authority",
        "capability_authority",
        "permit_authority",
        "execution_authority",
        "graph_admission_authority",
        "finding_authority",
        "report_delivery_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_snapshot(self) -> Self:
        refs = tuple(item.evidence_ref for item in self.evidence_bindings)
        if refs != tuple(sorted(set(refs))):
            raise ValueError("Web analysis local Evidence bindings must be unique and sorted")
        if tuple(item.model_signal() for item in self.evidence_bindings) != (
            self.model_projection.evidence_signals
        ):
            raise ValueError("Web analysis model signals differ from local Evidence bindings")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"snapshot_id", "snapshot_digest"},
        )
        digest = _digest("pajin.web-analysis.snapshot/v1", material, max_bytes=_MAX_SNAPSHOT_BYTES)
        snapshot_id = f"web-analysis-snapshot:{digest}"
        if self.snapshot_digest and self.snapshot_digest != digest:
            raise ValueError("Web analysis Snapshot Digest differs")
        if self.snapshot_id and self.snapshot_id != snapshot_id:
            raise ValueError("Web analysis Snapshot ID differs")
        object.__setattr__(self, "snapshot_digest", digest)
        object.__setattr__(self, "snapshot_id", snapshot_id)
        return self


class WebAnalysisDiagnosticDraft(_AliasWireModel):
    """One model-proposed rank with only code-owned semantics and opaque references."""

    rank: int = Field(strict=True, ge=1, le=3)
    diagnostic_id: DiagnosticId = Field(alias="diagnosticId")
    catalog_entry_id: _Identifier = Field(alias="catalogEntryId")
    hypothesis_id: _Identifier = Field(alias="hypothesisId")
    evidence_refs: tuple[_EvidenceRef, ...] = Field(
        alias="evidenceRefs",
        min_length=1,
        max_length=16,
    )

    @field_validator("rank", mode="before")
    @classmethod
    def require_integer_rank(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Web analysis diagnostic rank must be an integer")
        return value

    @field_validator("evidence_refs")
    @classmethod
    def require_canonical_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_refs(value, label="Web analysis diagnostic Evidence references")

    @model_validator(mode="after")
    def bind_code_owned_entry(self) -> Self:
        entry, hypothesis = _DIAGNOSTIC_CATALOG_ENTRIES[self.diagnostic_id]
        if self.catalog_entry_id != entry or self.hypothesis_id != hypothesis:
            raise ValueError("Web analysis diagnostic draft differs from code authority")
        return self


class WebAnalysisPathDraft(_AliasWireModel):
    """One model-proposed disposition for an exact code-owned attack-path shape."""

    catalog_entry_id: _Identifier = Field(alias="catalogEntryId")
    hypothesis_id: _Identifier = Field(alias="hypothesisId")
    issue_sequence: tuple[DiagnosticId, ...] = Field(
        alias="issueSequence",
        min_length=1,
        max_length=3,
    )
    disposition: PathDisposition
    evidence_refs: tuple[_EvidenceRef, ...] = Field(
        alias="evidenceRefs",
        min_length=1,
        max_length=16,
    )

    @field_validator("evidence_refs")
    @classmethod
    def require_canonical_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_refs(value, label="Web analysis path Evidence references")

    @model_validator(mode="after")
    def bind_code_owned_entry(self) -> Self:
        expected = _PATH_CATALOG_ENTRIES.get(self.issue_sequence)
        if (
            expected is None
            or self.catalog_entry_id != expected[0]
            or self.hypothesis_id != expected[1]
        ):
            raise ValueError("Web analysis path draft differs from code authority")
        return self


class WebAnalysisProposalDraft(_AliasWireModel):
    """Exact free-text-free model output; this object has no execution authority."""

    api_version: Literal["pajin.dev/web-analysis-proposal-draft/v1alpha1"] = Field(
        alias="apiVersion"
    )
    kind: Literal["WebAnalysisProposalDraft"]
    projection_id: str = Field(alias="projectionId", min_length=1, max_length=110)
    projection_digest: _Sha256 = Field(alias="projectionDigest")
    prioritized_diagnostics: tuple[
        WebAnalysisDiagnosticDraft,
        WebAnalysisDiagnosticDraft,
        WebAnalysisDiagnosticDraft,
    ] = Field(alias="prioritizedDiagnostics")
    path_assessments: tuple[WebAnalysisPathDraft, WebAnalysisPathDraft] = Field(
        alias="pathAssessments"
    )
    proposal_state: Literal["untrusted-model-output-not-authorized"] = Field(alias="proposalState")
    scope_expansion_authorized: Literal[False] = Field(alias="scopeExpansionAuthorized")
    tool_request_compiled: Literal[False] = Field(alias="toolRequestCompiled")
    capability_granted: Literal[False] = Field(alias="capabilityGranted")
    permit_granted: Literal[False] = Field(alias="permitGranted")
    execution_authorized: Literal[False] = Field(alias="executionAuthorized")
    graph_admission_authorized: Literal[False] = Field(alias="graphAdmissionAuthorized")
    finding_authorized: Literal[False] = Field(alias="findingAuthorized")
    report_delivery_authorized: Literal[False] = Field(alias="reportDeliveryAuthorized")

    @field_validator(
        "scope_expansion_authorized",
        "tool_request_compiled",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "graph_admission_authorized",
        "finding_authorized",
        "report_delivery_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_shape(self) -> Self:
        ranks = tuple(item.rank for item in self.prioritized_diagnostics)
        diagnostic_ids = tuple(item.diagnostic_id for item in self.prioritized_diagnostics)
        if ranks != (1, 2, 3) or set(diagnostic_ids) != set(_DIAGNOSTIC_CATALOG_ENTRIES):
            raise ValueError("Web analysis draft requires one exact contiguous rank per diagnostic")
        expected_paths = tuple(_PATH_CATALOG_ENTRIES)
        if tuple(item.issue_sequence for item in self.path_assessments) != expected_paths:
            raise ValueError("Web analysis draft requires the exact attack-path catalog order")
        return self


class CompiledWebAnalysisDiagnostic(_AliasWireModel):
    """Compiled advisory rank with hypothesis content reduced to digest and byte count."""

    rank: int = Field(strict=True, ge=1, le=3)
    diagnostic_id: DiagnosticId = Field(alias="diagnosticId")
    catalog_entry_id: _Identifier = Field(alias="catalogEntryId")
    hypothesis_digest: _Sha256 = Field(alias="hypothesisDigest")
    hypothesis_bytes: int = Field(alias="hypothesisBytes", strict=True, ge=1, le=200)
    hypothesis_content_embedded: Literal[False] = Field(alias="hypothesisContentEmbedded")
    evidence_refs: tuple[_EvidenceRef, ...] = Field(
        alias="evidenceRefs",
        min_length=1,
        max_length=16,
    )

    @field_validator("hypothesis_content_embedded", mode="before")
    @classmethod
    def require_false_marker(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator("evidence_refs")
    @classmethod
    def require_canonical_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_refs(value, label="Compiled Web analysis diagnostic Evidence references")

    @model_validator(mode="after")
    def bind_code_owned_entry(self) -> Self:
        entry, hypothesis = _DIAGNOSTIC_CATALOG_ENTRIES[self.diagnostic_id]
        if (
            self.catalog_entry_id != entry
            or self.hypothesis_digest != _text_digest(hypothesis)
            or self.hypothesis_bytes != len(hypothesis.encode("utf-8", errors="strict"))
        ):
            raise ValueError("Compiled Web analysis diagnostic differs from code authority")
        return self


class CompiledWebAnalysisPath(_AliasWireModel):
    """Compiled advisory path assessment without model-authored text."""

    catalog_entry_id: _Identifier = Field(alias="catalogEntryId")
    issue_sequence: tuple[DiagnosticId, ...] = Field(
        alias="issueSequence",
        min_length=1,
        max_length=3,
    )
    disposition: PathDisposition
    hypothesis_digest: _Sha256 = Field(alias="hypothesisDigest")
    hypothesis_bytes: int = Field(alias="hypothesisBytes", strict=True, ge=1, le=200)
    hypothesis_content_embedded: Literal[False] = Field(alias="hypothesisContentEmbedded")
    evidence_refs: tuple[_EvidenceRef, ...] = Field(
        alias="evidenceRefs",
        min_length=1,
        max_length=16,
    )

    @field_validator("hypothesis_content_embedded", mode="before")
    @classmethod
    def require_false_marker(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator("evidence_refs")
    @classmethod
    def require_canonical_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_refs(value, label="Compiled Web analysis path Evidence references")

    @model_validator(mode="after")
    def bind_code_owned_entry(self) -> Self:
        expected = _PATH_CATALOG_ENTRIES.get(self.issue_sequence)
        if (
            expected is None
            or self.catalog_entry_id != expected[0]
            or self.hypothesis_digest != _text_digest(expected[1])
            or self.hypothesis_bytes != len(expected[1].encode("utf-8", errors="strict"))
        ):
            raise ValueError("Compiled Web analysis path differs from code authority")
        return self


class WebAnalysisCompilationPolicy(_AliasWireModel):
    """Code-owned version pins for the v1alpha1 proposal compiler."""

    api_version: Literal["pajin.dev/web-analysis-compilation-policy/v1alpha1"] = Field(
        alias="apiVersion"
    )
    kind: Literal["WebAnalysisCompilationPolicy"]
    policy_digest: str = Field(alias="policyDigest", max_length=64)
    model_projection_schema_digest: _Sha256 = Field(alias="modelProjectionSchemaDigest")
    draft_schema_digest: _Sha256 = Field(alias="draftSchemaDigest")
    output_schema_digest: _Sha256 = Field(alias="outputSchemaDigest")
    required_diagnostic_count: Literal[3] = Field(alias="requiredDiagnosticCount")
    required_path_count: Literal[2] = Field(alias="requiredPathCount")
    free_text_allowed: Literal[False] = Field(alias="freeTextAllowed")
    execution_compilation_allowed: Literal[False] = Field(alias="executionCompilationAllowed")

    @field_validator("free_text_allowed", "execution_compilation_allowed", mode="before")
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_policy(self) -> Self:
        material = self.model_dump(mode="json", by_alias=True, exclude={"policy_digest"})
        digest = _digest("pajin.web-analysis.compilation-policy/v1", material)
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Web analysis Compilation Policy Digest differs")
        object.__setattr__(self, "policy_digest", digest)
        return self


class CompiledWebAnalysisProposal(_AliasWireModel):
    """Local content-addressed advisory result with exact source and projection lineage."""

    api_version: Literal["pajin.dev/compiled-web-analysis-proposal/v1alpha1"] = Field(
        alias="apiVersion"
    )
    kind: Literal["CompiledWebAnalysisProposal"]
    proposal_id: str = Field(alias="proposalId", max_length=110)
    proposal_digest: str = Field(alias="proposalDigest", max_length=64)
    compilation_policy_digest: _Sha256 = Field(alias="compilationPolicyDigest")
    model_projection_schema_digest: _Sha256 = Field(alias="modelProjectionSchemaDigest")
    draft_schema_digest: _Sha256 = Field(alias="draftSchemaDigest")
    output_schema_digest: _Sha256 = Field(alias="outputSchemaDigest")
    source_snapshot_id: str = Field(alias="sourceSnapshotId", min_length=1, max_length=110)
    source_snapshot_digest: _Sha256 = Field(alias="sourceSnapshotDigest")
    source_projection_id: str = Field(alias="sourceProjectionId", min_length=1, max_length=110)
    source_projection_digest: _Sha256 = Field(alias="sourceProjectionDigest")
    source_draft_digest: _Sha256 = Field(alias="sourceDraftDigest")
    source_run_id: str = Field(alias="sourceRunId", pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_index_digest: _Sha256 = Field(alias="sourceIndexDigest")
    source_plan_digest: _Sha256 = Field(alias="sourcePlanDigest")
    source_discovery_evidence_digest: _Sha256 = Field(alias="sourceDiscoveryEvidenceDigest")
    source_discovery_plan_digest: _Sha256 = Field(alias="sourceDiscoveryPlanDigest")
    source_discovery_result_digest: _Sha256 = Field(alias="sourceDiscoveryResultDigest")
    diagnostic_catalog_digest: _Sha256 = Field(alias="diagnosticCatalogDigest")
    diagnostic_bundle_digest: _Sha256 = Field(alias="diagnosticBundleDigest")
    evidence_bindings: tuple[WebAnalysisEvidenceBinding, ...] = Field(
        alias="evidenceBindings",
        min_length=1,
        max_length=16,
    )
    prioritized_diagnostics: tuple[
        CompiledWebAnalysisDiagnostic,
        CompiledWebAnalysisDiagnostic,
        CompiledWebAnalysisDiagnostic,
    ] = Field(alias="prioritizedDiagnostics")
    path_assessments: tuple[CompiledWebAnalysisPath, CompiledWebAnalysisPath] = Field(
        alias="pathAssessments"
    )
    compilation_state: Literal["compiled-proposal-not-authorized"] = Field(alias="compilationState")
    model_output_authoritative: Literal[False] = Field(alias="modelOutputAuthoritative")
    diagnostic_selection_authoritative: Literal[False] = Field(
        alias="diagnosticSelectionAuthoritative"
    )
    path_assessment_authoritative: Literal[False] = Field(alias="pathAssessmentAuthoritative")
    scope_expansion_authorized: Literal[False] = Field(alias="scopeExpansionAuthorized")
    tool_request_compiled: Literal[False] = Field(alias="toolRequestCompiled")
    capability_granted: Literal[False] = Field(alias="capabilityGranted")
    permit_granted: Literal[False] = Field(alias="permitGranted")
    execution_authorized: Literal[False] = Field(alias="executionAuthorized")
    graph_admission_authorized: Literal[False] = Field(alias="graphAdmissionAuthorized")
    finding_authorized: Literal[False] = Field(alias="findingAuthorized")
    report_delivery_authorized: Literal[False] = Field(alias="reportDeliveryAuthorized")

    @field_validator(
        "model_output_authoritative",
        "diagnostic_selection_authoritative",
        "path_assessment_authoritative",
        "scope_expansion_authorized",
        "tool_request_compiled",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "graph_admission_authorized",
        "finding_authorized",
        "report_delivery_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_proposal(self) -> Self:
        policy = registered_web_analysis_compilation_policy()
        if (
            self.compilation_policy_digest != policy.policy_digest
            or self.model_projection_schema_digest != policy.model_projection_schema_digest
            or self.draft_schema_digest != policy.draft_schema_digest
            or self.output_schema_digest != policy.output_schema_digest
        ):
            raise ValueError("Compiled Web analysis Proposal differs from compiler policy")
        refs = tuple(item.evidence_ref for item in self.evidence_bindings)
        if refs != tuple(sorted(set(refs))):
            raise ValueError("Compiled Web analysis Evidence bindings must be unique and sorted")
        if tuple(item.rank for item in self.prioritized_diagnostics) != (1, 2, 3):
            raise ValueError("Compiled Web analysis diagnostic ranks differ")
        if set(item.diagnostic_id for item in self.prioritized_diagnostics) != set(
            _DIAGNOSTIC_CATALOG_ENTRIES
        ):
            raise ValueError("Compiled Web analysis diagnostics differ from code authority")
        if tuple(item.issue_sequence for item in self.path_assessments) != tuple(
            _PATH_CATALOG_ENTRIES
        ):
            raise ValueError("Compiled Web analysis paths differ from code authority")
        binding_by_ref = {item.evidence_ref: item for item in self.evidence_bindings}
        for item in (*self.prioritized_diagnostics, *self.path_assessments):
            for ref in item.evidence_refs:
                binding = binding_by_ref.get(ref)
                if binding is None or item.catalog_entry_id not in binding.supports_catalog_entries:
                    raise ValueError(
                        "Compiled Web analysis Evidence does not resolve to its catalog entry"
                    )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"proposal_id", "proposal_digest"},
        )
        digest = _digest(
            "pajin.web-analysis.compiled-proposal/v1",
            material,
            max_bytes=_PROPOSAL_LIMIT,
        )
        proposal_id = f"compiled-web-analysis:{digest}"
        if self.proposal_digest and self.proposal_digest != digest:
            raise ValueError("Compiled Web analysis Proposal Digest differs")
        if self.proposal_id and self.proposal_id != proposal_id:
            raise ValueError("Compiled Web analysis Proposal ID differs")
        object.__setattr__(self, "proposal_digest", digest)
        object.__setattr__(self, "proposal_id", proposal_id)
        return self


_ALL_CATALOG_ENTRY_IDS: Final = frozenset(
    [entry for entry, _ in _DIAGNOSTIC_CATALOG_ENTRIES.values()]
    + [entry for entry, _ in _PATH_CATALOG_ENTRIES.values()]
)
_PROPOSAL_LIMIT: Final = _MAX_PROPOSAL_BYTES


def build_web_analysis_snapshot(
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    expected_run_id: str,
    expected_root_digest: str,
) -> WebAnalysisSnapshot:
    """Strictly reload and bind one sealed source with independent exact anchors."""

    return _build_web_analysis_snapshot_with_loader(
        source,
        source_loader=load_verified_authenticated_discovery,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
    )


def _build_web_analysis_snapshot_with_loader(
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    source_loader: _VerifiedSourceLoader,
    expected_run_id: str,
    expected_root_digest: str,
) -> WebAnalysisSnapshot:
    """Internal construction seam; public callers use the production sealed loader."""

    try:
        current = _current_source(
            source,
            source_loader=source_loader,
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
        )
        profile, descriptor = _current_production_authority(current.plan)
        evidence = current.discovery
        bindings = _build_evidence_bindings(
            source=current,
            evidence=evidence,
        )
        projection_diagnostics = cast(
            tuple[
                WebAnalysisProjectionDiagnostic,
                WebAnalysisProjectionDiagnostic,
                WebAnalysisProjectionDiagnostic,
            ],
            tuple(
                WebAnalysisProjectionDiagnostic(
                    diagnosticId=diagnostic_id,
                    catalogEntryId=_DIAGNOSTIC_CATALOG_ENTRIES[diagnostic_id][0],
                    allowedHypothesisIds=(_DIAGNOSTIC_CATALOG_ENTRIES[diagnostic_id][1],),
                )
                for diagnostic_id in descriptor.diagnostic_order
            ),
        )
        projection_paths = cast(
            tuple[WebAnalysisProjectionPath, WebAnalysisProjectionPath],
            tuple(
                WebAnalysisProjectionPath(
                    catalogEntryId=_PATH_CATALOG_ENTRIES[sequence][0],
                    issueSequence=sequence,
                    allowedHypothesisIds=(_PATH_CATALOG_ENTRIES[sequence][1],),
                    allowedDispositions=("investigate", "insufficient-evidence"),
                )
                for sequence in descriptor.attack_path_issue_sequences
            ),
        )
        projection = WebAnalysisModelProjection(
            apiVersion=WEB_ANALYSIS_MODEL_PROJECTION_API_VERSION,
            kind="WebAnalysisModelProjection",
            projectionId="",
            projectionDigest="",
            diagnostics=projection_diagnostics,
            attackPaths=projection_paths,
            evidenceSignals=tuple(binding.model_signal() for binding in bindings),
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
        return WebAnalysisSnapshot(
            apiVersion=WEB_ANALYSIS_SNAPSHOT_API_VERSION,
            kind="WebAnalysisSnapshot",
            snapshotId="",
            snapshotDigest="",
            sourceRunId=current.verification.run_id,
            sourceRootDigest=current.verification.root_digest,
            sourceIndexDigest=current.index.index_digest,
            sourcePlanDigest=current.plan.plan_digest,
            sourceDiscoveryEvidenceDigest=evidence.evidence_digest,
            sourceDiscoveryPlanDigest=evidence.discovery_plan.plan_digest,
            sourceDiscoveryResultDigest=evidence.discovery_result.result_digest,
            profileRegistryDigest=profile.registry_digest,
            profileDigest=profile.profile_digest,
            adapterCatalogDigest=profile.catalog_digest,
            diagnosticCatalogDigest=descriptor.catalog_digest,
            diagnosticBundleId=descriptor.bundle_id,
            diagnosticBundleDigest=descriptor.bundle_digest,
            adapterImplementationId=descriptor.adapter_implementation_id,
            adapterImplementationDigest=descriptor.adapter_implementation_digest,
            executorId=descriptor.executor_id,
            executorImplementationDigest=descriptor.executor_implementation_digest,
            pathBuilderId=descriptor.path_builder_id,
            pathBuilderImplementationDigest=descriptor.path_builder_implementation_digest,
            evidenceBindings=bindings,
            modelProjection=projection,
            snapshotState="sealed-source-bound-proposal-only",
            secretMaterialEmbedded=False,
            targetContentModelVisible=False,
            scopeExpansionAuthority=False,
            toolRequestAuthority=False,
            capabilityAuthority=False,
            permitAuthority=False,
            executionAuthority=False,
            graphAdmissionAuthority=False,
            findingAuthority=False,
            reportDeliveryAuthority=False,
        )
    except (AttributeError, TypeError, UnicodeError, ValidationError, ValueError) as exc:
        if isinstance(exc, WebAnalysisProposalError):
            raise
        raise WebAnalysisProposalError("Web analysis Snapshot construction failed closed") from exc


def parse_web_analysis_proposal_draft(
    content: bytes,
    *,
    expected_projection: WebAnalysisModelProjection,
) -> WebAnalysisProposalDraft:
    """Strict-decode an alias-only, free-text-free model proposal."""

    try:
        raw = parse_strict_json_bytes(
            content,
            label="Web analysis Provider draft",
            max_bytes=_MAX_DRAFT_BYTES,
            max_depth=12,
            max_nodes=512,
        )
        if type(raw) is not dict:
            raise TypeError("Web analysis draft wire must be a JSON object")
        _reject_forbidden_structural_keys(raw)
        draft = WebAnalysisProposalDraft.model_validate(raw)
        projection = _canonical_model(expected_projection, WebAnalysisModelProjection)
        _require_draft_matches_projection(draft, projection)
        return draft
    except (AttributeError, TypeError, UnicodeError, ValidationError, ValueError) as exc:
        if isinstance(exc, WebAnalysisProposalError):
            raise
        raise WebAnalysisProposalError(
            "Web analysis draft wire differs from the advertised proposal schema"
        ) from exc


def compile_web_analysis_proposal(
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    snapshot: WebAnalysisSnapshot,
    draft: WebAnalysisProposalDraft,
    expected_run_id: str,
    expected_root_digest: str,
) -> CompiledWebAnalysisProposal:
    """Compile only after a production reload under independent exact anchors."""

    return _compile_web_analysis_proposal_with_loader(
        source=source,
        snapshot=snapshot,
        draft=draft,
        source_loader=load_verified_authenticated_discovery,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
    )


def _compile_web_analysis_proposal_with_loader(
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    snapshot: WebAnalysisSnapshot,
    draft: WebAnalysisProposalDraft,
    source_loader: _VerifiedSourceLoader,
    expected_run_id: str,
    expected_root_digest: str,
) -> CompiledWebAnalysisProposal:
    """Internal compiler seam; public callers use the production sealed loader."""

    try:
        current_snapshot = _build_web_analysis_snapshot_with_loader(
            source,
            source_loader=source_loader,
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
        )
        canonical_snapshot = _canonical_model(snapshot, WebAnalysisSnapshot)
        if canonical_snapshot != snapshot or canonical_snapshot != current_snapshot:
            raise ValueError("Web analysis Snapshot differs from current sealed source authority")
        _require_declared_model_state(draft)
        draft_bytes = canonical_json_bytes(
            draft.model_dump(mode="json", by_alias=True),
            label="Web analysis draft recompilation",
            max_bytes=_MAX_DRAFT_BYTES,
        )
        canonical_draft = parse_web_analysis_proposal_draft(
            draft_bytes,
            expected_projection=current_snapshot.model_projection,
        )
        if canonical_draft != draft:
            raise ValueError("Web analysis draft differs from its strict wire representation")
        policy = registered_web_analysis_compilation_policy()
        compiled_diagnostics = cast(
            tuple[
                CompiledWebAnalysisDiagnostic,
                CompiledWebAnalysisDiagnostic,
                CompiledWebAnalysisDiagnostic,
            ],
            tuple(
                CompiledWebAnalysisDiagnostic(
                    rank=item.rank,
                    diagnosticId=item.diagnostic_id,
                    catalogEntryId=item.catalog_entry_id,
                    hypothesisDigest=_text_digest(item.hypothesis_id),
                    hypothesisBytes=len(item.hypothesis_id.encode("utf-8", errors="strict")),
                    hypothesisContentEmbedded=False,
                    evidenceRefs=item.evidence_refs,
                )
                for item in canonical_draft.prioritized_diagnostics
            ),
        )
        compiled_paths = cast(
            tuple[CompiledWebAnalysisPath, CompiledWebAnalysisPath],
            tuple(
                CompiledWebAnalysisPath(
                    catalogEntryId=item.catalog_entry_id,
                    issueSequence=item.issue_sequence,
                    disposition=item.disposition,
                    hypothesisDigest=_text_digest(item.hypothesis_id),
                    hypothesisBytes=len(item.hypothesis_id.encode("utf-8", errors="strict")),
                    hypothesisContentEmbedded=False,
                    evidenceRefs=item.evidence_refs,
                )
                for item in canonical_draft.path_assessments
            ),
        )
        return CompiledWebAnalysisProposal(
            apiVersion=COMPILED_WEB_ANALYSIS_PROPOSAL_API_VERSION,
            kind="CompiledWebAnalysisProposal",
            proposalId="",
            proposalDigest="",
            compilationPolicyDigest=policy.policy_digest,
            modelProjectionSchemaDigest=policy.model_projection_schema_digest,
            draftSchemaDigest=policy.draft_schema_digest,
            outputSchemaDigest=policy.output_schema_digest,
            sourceSnapshotId=current_snapshot.snapshot_id,
            sourceSnapshotDigest=current_snapshot.snapshot_digest,
            sourceProjectionId=current_snapshot.model_projection.projection_id,
            sourceProjectionDigest=current_snapshot.model_projection.projection_digest,
            sourceDraftDigest=_draft_digest(canonical_draft),
            sourceRunId=current_snapshot.source_run_id,
            sourceRootDigest=current_snapshot.source_root_digest,
            sourceIndexDigest=current_snapshot.source_index_digest,
            sourcePlanDigest=current_snapshot.source_plan_digest,
            sourceDiscoveryEvidenceDigest=current_snapshot.source_discovery_evidence_digest,
            sourceDiscoveryPlanDigest=current_snapshot.source_discovery_plan_digest,
            sourceDiscoveryResultDigest=current_snapshot.source_discovery_result_digest,
            diagnosticCatalogDigest=current_snapshot.diagnostic_catalog_digest,
            diagnosticBundleDigest=current_snapshot.diagnostic_bundle_digest,
            evidenceBindings=current_snapshot.evidence_bindings,
            prioritizedDiagnostics=compiled_diagnostics,
            pathAssessments=compiled_paths,
            compilationState="compiled-proposal-not-authorized",
            modelOutputAuthoritative=False,
            diagnosticSelectionAuthoritative=False,
            pathAssessmentAuthoritative=False,
            scopeExpansionAuthorized=False,
            toolRequestCompiled=False,
            capabilityGranted=False,
            permitGranted=False,
            executionAuthorized=False,
            graphAdmissionAuthorized=False,
            findingAuthorized=False,
            reportDeliveryAuthorized=False,
        )
    except (AttributeError, TypeError, UnicodeError, ValidationError, ValueError) as exc:
        if isinstance(exc, WebAnalysisProposalError):
            raise
        raise WebAnalysisProposalError("Web analysis proposal compilation failed closed") from exc


def verify_compiled_web_analysis_proposal(
    proposal: CompiledWebAnalysisProposal,
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    snapshot: WebAnalysisSnapshot,
    draft: WebAnalysisProposalDraft,
    expected_run_id: str,
    expected_root_digest: str,
) -> CompiledWebAnalysisProposal:
    """Verify only after a production reload under independent exact anchors."""

    return _verify_compiled_web_analysis_proposal_with_loader(
        proposal,
        source=source,
        snapshot=snapshot,
        draft=draft,
        source_loader=load_verified_authenticated_discovery,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
    )


def _verify_compiled_web_analysis_proposal_with_loader(
    proposal: CompiledWebAnalysisProposal,
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    snapshot: WebAnalysisSnapshot,
    draft: WebAnalysisProposalDraft,
    source_loader: _VerifiedSourceLoader,
    expected_run_id: str,
    expected_root_digest: str,
) -> CompiledWebAnalysisProposal:
    """Internal verifier seam; public callers use the production sealed loader."""

    try:
        canonical = _canonical_model(proposal, CompiledWebAnalysisProposal)
        expected = _compile_web_analysis_proposal_with_loader(
            source=source,
            snapshot=snapshot,
            draft=draft,
            source_loader=source_loader,
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
        )
        if canonical != proposal or canonical != expected:
            raise ValueError("Compiled Web analysis Proposal differs from current authority")
        return canonical.model_copy(deep=True)
    except (AttributeError, TypeError, UnicodeError, ValidationError, ValueError) as exc:
        if isinstance(exc, WebAnalysisProposalError):
            raise
        raise WebAnalysisProposalError(
            "Compiled Web analysis Proposal verification failed closed"
        ) from exc


def registered_web_analysis_compilation_policy() -> WebAnalysisCompilationPolicy:
    """Return the single code-owned v1alpha1 compilation policy."""

    return WebAnalysisCompilationPolicy(
        apiVersion=WEB_ANALYSIS_COMPILATION_POLICY_API_VERSION,
        kind="WebAnalysisCompilationPolicy",
        policyDigest="",
        modelProjectionSchemaDigest=_schema_digest(
            WebAnalysisModelProjection,
            "pajin.web-analysis.schema/model-projection/v1",
        ),
        draftSchemaDigest=_schema_digest(
            WebAnalysisProposalDraft,
            "pajin.web-analysis.schema/proposal-draft/v1",
        ),
        outputSchemaDigest=_schema_digest(
            CompiledWebAnalysisProposal,
            "pajin.web-analysis.schema/compiled-proposal/v1",
        ),
        requiredDiagnosticCount=3,
        requiredPathCount=2,
        freeTextAllowed=False,
        executionCompilationAllowed=False,
    )


def _current_source(
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    source_loader: _VerifiedSourceLoader,
    expected_run_id: str,
    expected_root_digest: str,
) -> VerifiedAuthenticatedDiscoveryRun:
    if type(source) is not VerifiedAuthenticatedDiscoveryRun:
        raise TypeError("Web analysis source is not a verified authenticated discovery Run")
    source_run_id = source.verification.run_id
    source_root_digest = source.verification.root_digest
    run_id = expected_run_id
    root_digest = expected_root_digest
    if _RUN_ID_RE.fullmatch(run_id) is None or _SHA256_RE.fullmatch(root_digest) is None:
        raise ValueError("Web analysis source anchors are invalid")
    if run_id != source_run_id or root_digest != source_root_digest:
        raise ValueError("Web analysis source differs from independently supplied anchors")
    if not callable(source_loader):
        raise TypeError("Web analysis source loader is not callable")
    loaded = source_loader(
        source.run_path,
        expected_run_id=run_id,
        expected_root_digest=root_digest,
    )
    if type(loaded) is not VerifiedAuthenticatedDiscoveryRun or loaded != source:
        raise ValueError("Web analysis reloaded source differs from the supplied verified source")
    return _canonical_source(loaded)


def _canonical_source(
    source: VerifiedAuthenticatedDiscoveryRun,
) -> VerifiedAuthenticatedDiscoveryRun:
    for component in (
        source.verification,
        source.plan,
        source.authorization,
        source.discovery,
        source.index,
    ):
        _require_declared_model_state(component)
    verification = RunIntegrityVerification.model_validate(
        source.verification.model_dump(mode="json")
    )
    plan = WebAssessmentPlan.model_validate(source.plan.model_dump(mode="json", by_alias=True))
    authorization = LocalWebAssessmentAuthorization.model_validate(
        source.authorization.model_dump(mode="json", by_alias=True)
    )
    discovery = AuthenticatedDiscoveryEvidence.model_validate(
        source.discovery.model_dump(mode="json", by_alias=True)
    )
    index = AuthenticatedDiscoveryRunIndex.model_validate(
        source.index.model_dump(mode="json", by_alias=True)
    )
    canonical = VerifiedAuthenticatedDiscoveryRun(
        run_path=source.run_path,
        verification=verification,
        plan=plan,
        authorization=authorization,
        discovery=discovery,
        index=index,
    )
    expected_discovery_plan = code_owned_authenticated_discovery_plan(plan)
    expected_account_reference_digest = _digest(
        "pajin.web-assessment.authenticated-discovery-account-reference/v1",
        {
            "adapterImplementationId": plan.adapter_implementation_id,
            "authorizationId": authorization.authorization_id,
            "origin": plan.origin,
            "planDigest": plan.plan_digest,
            "provisionedAt": index.account_provisioned_at.astimezone(UTC).isoformat(),
            "targetProduct": plan.target_product,
            "targetVersion": index.target_version,
        },
    )
    if (
        canonical != source
        or verification.valid is not True
        or verification.run_id != index.run_id
        or index.plan_digest != plan.plan_digest
        or index.authorization_id != authorization.authorization_id
        or authorization.plan_digest != plan.plan_digest
        or index.origin != plan.origin
        or authorization.origin != plan.origin
        or discovery.discovery_plan != expected_discovery_plan
        or index.discovery_evidence_digest != discovery.evidence_digest
        or index.discovery_plan_digest != discovery.discovery_plan.plan_digest
        or index.discovery_result_digest != discovery.discovery_result.result_digest
        or index.passive_request_count != len(discovery.request_evidence)
        or discovery.discovery_plan.origin != plan.origin
        or discovery.discovery_result.origin != plan.origin
        or index.account_reference_digest != expected_account_reference_digest
        or not authorization.approved_at <= index.account_provisioned_at <= index.started_at
        or index.account_provisioned_at >= authorization.expires_at
        or any(
            browser_discovery_request_path_rejection(
                origin=plan.origin,
                url=plan.origin + request.path,
            )
            is not None
            for request in discovery.request_evidence
        )
        or source.semantics != "source-integrity-only"
        or source.independent_replay_verified is not False
        or source.execution_authority is not False
        or source.finding_authority is not False
        or source.graph_admission_authority is not False
    ):
        raise ValueError("Web analysis source integrity object is not exact and canonical")
    authorization.require_current(plan=plan, now=index.started_at)
    authorization.require_current(plan=plan, now=index.finished_at)
    return canonical


def _current_production_authority(
    plan: WebAssessmentPlan,
) -> tuple[ResolvedGovernedWebAdapterProfile, DiagnosticBundleDescriptor]:
    profile_registry = production_governed_web_adapter_profile_registry()
    matches = [
        profile_registry.resolve(adapter_reference=reference, origin=origin)
        for reference, origin in profile_registry.references()
        if origin == plan.origin
    ]
    if len(matches) != 1:
        raise ValueError("Web analysis source is not in the closed production profile registry")
    profile = matches[0]
    if profile.plan != plan or profile.implementation_id != plan.adapter_implementation_id:
        raise ValueError("Web analysis source Plan differs from the current production profile")
    diagnostic_catalog = production_diagnostic_bundle_catalog()
    descriptor = diagnostic_catalog.resolve(
        adapter_implementation_id=profile.implementation_id,
        adapter_implementation_digest=profile.implementation_digest,
    )
    canonical_plan = diagnostic_catalog.require_code_owned_plan(descriptor=descriptor, plan=plan)
    if (
        canonical_plan != plan
        or descriptor.diagnostic_order != tuple(_DIAGNOSTIC_CATALOG_ENTRIES)
        or descriptor.attack_path_issue_sequences != tuple(_PATH_CATALOG_ENTRIES)
    ):
        raise ValueError("Web analysis diagnostic catalog differs from v1alpha1 authority")
    return profile, descriptor


def _build_evidence_bindings(
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    evidence: AuthenticatedDiscoveryEvidence,
) -> tuple[WebAnalysisEvidenceBinding, ...]:
    key = bytes.fromhex(source.verification.root_digest)
    items: list[WebAnalysisEvidenceBinding] = []
    all_entries = tuple(sorted(_ALL_CATALOG_ENTRY_IDS))
    sql_login_entry = _DIAGNOSTIC_CATALOG_ENTRIES["sql-login"][0]
    object_access_entry = _DIAGNOSTIC_CATALOG_ENTRIES["object-access"][0]
    dom_xss_entry = _DIAGNOSTIC_CATALOG_ENTRIES["dom-xss"][0]
    login_object_path_entry = _PATH_CATALOG_ENTRIES[("sql-login", "object-access")][0]
    dom_xss_path_entry = _PATH_CATALOG_ENTRIES[("dom-xss",)][0]
    form_entries = tuple(
        sorted(
            (
                sql_login_entry,
                dom_xss_entry,
                login_object_path_entry,
                dom_xss_path_entry,
            )
        )
    )
    request_entries = tuple(sorted((object_access_entry, login_object_path_entry)))
    discovery_result = evidence.discovery_result
    aggregates: tuple[
        tuple[EvidenceSourceKind, str, str, SignalKind, int, tuple[str, ...]], ...
    ] = (
        (
            "discovery-route-set",
            "authenticated-discovery-route-set",
            _digest(
                "pajin.web-analysis.source-route-set/v1",
                [
                    {
                        "routeId": route.route_id,
                        "structureDigest": route.structure_digest,
                        "depth": route.depth,
                        "source": route.source,
                    }
                    for route in discovery_result.routes
                ],
            ),
            "discovered-route-count",
            len(discovery_result.routes),
            all_entries,
        ),
        (
            "discovery-form-set",
            "authenticated-discovery-form-set",
            _digest(
                "pajin.web-analysis.source-form-set/v1",
                [
                    {
                        "formId": form.form_id,
                        "structureDigest": form.structure_digest,
                    }
                    for form in discovery_result.forms
                ],
            ),
            "discovered-form-count",
            len(discovery_result.forms),
            form_entries,
        ),
        (
            "discovery-control-set",
            "authenticated-discovery-control-set",
            _digest(
                "pajin.web-analysis.source-control-set/v1",
                [
                    {
                        "formId": form.form_id,
                        "observedControlCount": form.observed_control_count,
                    }
                    for form in discovery_result.forms
                ],
            ),
            "discovered-control-count",
            sum(form.observed_control_count for form in discovery_result.forms),
            form_entries,
        ),
        (
            "passive-request-set",
            "authenticated-passive-request-set",
            evidence.request_evidence_digest,
            "passive-request-count",
            len(evidence.request_evidence),
            request_entries,
        ),
    )
    for source_kind, source_identifier, source_digest, signal_kind, count, supports in aggregates:
        items.append(
            _binding(
                key=key,
                source_kind=source_kind,
                source_identifier=source_identifier,
                source_digest=source_digest,
                signal_kind=signal_kind,
                count=count,
                supports=supports,
            )
        )
    ordered = tuple(sorted(items, key=lambda item: item.evidence_ref))
    if len({item.evidence_ref for item in ordered}) != len(ordered):
        raise ValueError("Web analysis opaque Evidence reference collision")
    return ordered


def _binding(
    *,
    key: bytes,
    source_kind: EvidenceSourceKind,
    source_identifier: str,
    source_digest: str,
    signal_kind: SignalKind,
    count: int,
    supports: tuple[str, ...],
) -> WebAnalysisEvidenceBinding:
    material = {
        "sourceKind": source_kind,
        "sourceIdentifier": source_identifier,
        "sourceDigest": source_digest,
        "signalKind": signal_kind,
    }
    encoded = canonical_json_bytes(material, label="Web analysis opaque Evidence identity")
    opaque = hmac.new(
        key,
        b"pajin.web-analysis.opaque-evidence-ref/v1\x00" + encoded,
        sha256,
    ).hexdigest()[:32]
    return WebAnalysisEvidenceBinding(
        evidenceRef=f"wae_{opaque}",
        sourceKind=source_kind,
        sourceIdentifier=source_identifier,
        sourceDigest=source_digest,
        signalKind=signal_kind,
        countBucket=_count_bucket(count),
        supportsCatalogEntries=tuple(sorted(set(supports))),
    )


def _require_draft_matches_projection(
    draft: WebAnalysisProposalDraft,
    projection: WebAnalysisModelProjection,
) -> None:
    if (
        draft.projection_id != projection.projection_id
        or draft.projection_digest != projection.projection_digest
    ):
        raise ValueError("Web analysis draft refers to another Model Projection")
    projected_diagnostics = {item.diagnostic_id: item for item in projection.diagnostics}
    projected_paths = {item.issue_sequence: item for item in projection.attack_paths}
    signal_by_ref = {item.evidence_ref: item for item in projection.evidence_signals}
    for diagnostic_draft in draft.prioritized_diagnostics:
        projected_diagnostic = projected_diagnostics.get(diagnostic_draft.diagnostic_id)
        if (
            projected_diagnostic is None
            or diagnostic_draft.catalog_entry_id != projected_diagnostic.catalog_entry_id
            or diagnostic_draft.hypothesis_id not in projected_diagnostic.allowed_hypothesis_ids
        ):
            raise ValueError("Web analysis diagnostic draft is not in the current projection")
        _require_supported_refs(
            diagnostic_draft.evidence_refs,
            catalog_entry_id=diagnostic_draft.catalog_entry_id,
            signal_by_ref=signal_by_ref,
        )
    for path_draft in draft.path_assessments:
        projected_path = projected_paths.get(path_draft.issue_sequence)
        if (
            projected_path is None
            or path_draft.catalog_entry_id != projected_path.catalog_entry_id
            or path_draft.hypothesis_id not in projected_path.allowed_hypothesis_ids
            or path_draft.disposition not in projected_path.allowed_dispositions
        ):
            raise ValueError("Web analysis path draft is not in the current projection")
        _require_supported_refs(
            path_draft.evidence_refs,
            catalog_entry_id=path_draft.catalog_entry_id,
            signal_by_ref=signal_by_ref,
        )


def _require_supported_refs(
    refs: tuple[str, ...],
    *,
    catalog_entry_id: str,
    signal_by_ref: Mapping[str, WebAnalysisEvidenceSignal],
) -> None:
    for ref in refs:
        signal = signal_by_ref.get(ref)
        if signal is None:
            raise ValueError("Web analysis draft references foreign or stale Evidence")
        if catalog_entry_id not in signal.supports_catalog_entries:
            raise ValueError("Web analysis draft Evidence does not support its catalog entry")


def _reject_forbidden_structural_keys(value: object) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, nested in item.items():
                if type(key) is not str:
                    raise ValueError("Web analysis draft JSON object key is not text")
                normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
                if normalized in _FORBIDDEN_STRUCTURAL_KEYS:
                    raise ValueError("Web analysis draft contains a forbidden structural key")
                stack.append(nested)
        elif isinstance(item, list):
            stack.extend(item)


def _canonical_model[T: BaseModel](value: T, model: type[T]) -> T:
    if type(value) is not model:
        raise TypeError("Web analysis contract object has a non-canonical runtime type")
    _require_declared_model_state(value)
    return model.model_validate(value.model_dump(mode="json", by_alias=True))


def _require_declared_model_state(value: object) -> None:
    """Reject hidden state injected by validation-bypassing Pydantic copy operations."""

    stack = [value]
    visited: set[int] = set()
    while stack:
        item = stack.pop()
        if isinstance(item, BaseModel):
            identity = id(item)
            if identity in visited:
                continue
            visited.add(identity)
            declared = set(type(item).model_fields)
            stored = vars(item)
            if not set(stored).issubset(declared) or getattr(item, "__pydantic_extra__", None):
                raise ValueError("Web analysis contract contains undeclared model state")
            stack.extend(stored[name] for name in declared if name in stored)
        elif isinstance(item, Mapping):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


def _count_bucket(count: int) -> CountBucket:
    if type(count) is not int or count < 0:
        raise ValueError("Web analysis signal count is invalid")
    if count == 0:
        return "zero"
    if count == 1:
        return "one"
    if count <= 5:
        return "two-to-five"
    if count <= 20:
        return "six-to-twenty"
    return "over-twenty"


def _schema_digest(model: type[BaseModel], domain: str) -> str:
    return _digest(domain, model.model_json_schema(mode="validation", by_alias=True))


def _draft_digest(draft: WebAnalysisProposalDraft) -> str:
    return _digest(
        "pajin.web-analysis.proposal-draft/v1",
        draft.model_dump(mode="json", by_alias=True),
    )


def _text_digest(value: str) -> str:
    encoded = value.encode("utf-8", errors="strict")
    return sha256(b"pajin.web-analysis.hypothesis-id/v1\x00" + encoded).hexdigest()


def _digest(domain: str, value: object, *, max_bytes: int = _MAX_COMPONENT_BYTES) -> str:
    encoded = canonical_json_bytes(
        value,
        label="Web analysis content address",
        max_bytes=max_bytes,
    )
    return sha256(domain.encode("ascii", errors="strict") + b"\x00" + encoded).hexdigest()


__all__ = [
    "COMPILED_WEB_ANALYSIS_PROPOSAL_API_VERSION",
    "WEB_ANALYSIS_COMPILATION_POLICY_API_VERSION",
    "WEB_ANALYSIS_MODEL_PROJECTION_API_VERSION",
    "WEB_ANALYSIS_PROPOSAL_DRAFT_API_VERSION",
    "WEB_ANALYSIS_SNAPSHOT_API_VERSION",
    "CompiledWebAnalysisDiagnostic",
    "CompiledWebAnalysisPath",
    "CompiledWebAnalysisProposal",
    "WebAnalysisCompilationPolicy",
    "WebAnalysisDiagnosticDraft",
    "WebAnalysisEvidenceBinding",
    "WebAnalysisEvidenceSignal",
    "WebAnalysisModelProjection",
    "WebAnalysisPathDraft",
    "WebAnalysisProjectionDiagnostic",
    "WebAnalysisProjectionPath",
    "WebAnalysisProposalDraft",
    "WebAnalysisProposalError",
    "WebAnalysisSnapshot",
    "build_web_analysis_snapshot",
    "compile_web_analysis_proposal",
    "parse_web_analysis_proposal_draft",
    "registered_web_analysis_compilation_policy",
    "verify_compiled_web_analysis_proposal",
]
