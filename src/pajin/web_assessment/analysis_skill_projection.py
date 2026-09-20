"""SKILL-002 exact selection and split projection for a future WEB-007 successor call.

The preparation Run produced here performs no Provider, Tool, Gateway, Worker, or target action.
It binds reviewed Skill instructions for a future developer message separately from the existing
tainted opaque evidence projection that belongs in a future user message.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Final, Literal, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pajin.agentic.models import (
    AnalysisSkillReference,
    ExploitGroupDefinition,
    build_web_exploit_group,
)
from pajin.domain.models import StrictModel
from pajin.domain.orchestration import AgentRole
from pajin.runtime.store import (
    RunIntegrityVerification,
    RunStore,
    SealedArtifact,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
    verify_run_integrity,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json
from pajin.skills.catalog import (
    ASSESS_WEB_OBJECT_ACCESS_SKILL_ID,
    ASSESS_WEB_SQLI_SKILL_ID,
    ASSESS_WEB_XSS_SKILL_ID,
    COMPOSE_WEB_ATTACK_PATH_SKILL_ID,
    WRITE_WEB_SECURITY_FINDING_SKILL_ID,
    built_in_analysis_skill_registry,
    built_in_proposal_analysis_skill_registry,
    resolve_installed_analysis_skill_registry,
)
from pajin.skills.models import (
    SkillLifecycleStage,
    SkillRegistryRef,
    canonical_skill_contract,
    canonical_skill_json,
)
from pajin.skills.selection import (
    AnalysisSkillInstructionProjection,
    AnalysisSkillSelectionPolicy,
    AnalysisSkillSelectionReceipt,
    ProposalOnlySkillQualificationSet,
    build_analysis_skill_instruction_projection_from_code_owned_policy,
    qualify_proposal_only_skill_registry,
    select_analysis_skills_from_code_owned_policy,
)
from pajin.web_assessment.analysis_proposal import (
    WebAnalysisModelProjection,
    WebAnalysisSnapshot,
    _build_web_analysis_snapshot_with_loader,
    build_web_analysis_snapshot,
)
from pajin.web_assessment.discovery_artifact import (
    VerifiedAuthenticatedDiscoveryRun,
    load_verified_authenticated_discovery,
)

WEB_ANALYSIS_SKILL_PROJECTION_BUNDLE_API_VERSION: Literal[
    "pajin.dev/web-analysis-skill-projection-bundle/v1alpha1"
] = "pajin.dev/web-analysis-skill-projection-bundle/v1alpha1"
WEB_ANALYSIS_SKILL_BOUND_SNAPSHOT_API_VERSION: Literal[
    "pajin.dev/web-analysis-skill-bound-snapshot/v1alpha1"
] = "pajin.dev/web-analysis-skill-bound-snapshot/v1alpha1"
WEB_ANALYSIS_SKILL_PROJECTION_INDEX_API_VERSION: Literal[
    "pajin.dev/web-analysis-skill-projection-index/v1alpha1"
] = "pajin.dev/web-analysis-skill-projection-index/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_RUN_ID_PATTERN: Final = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
_SHA256_PATTERN: Final = re.compile(r"^[a-f0-9]{64}$")
_MAX_BUNDLE_BYTES = 64 * 1024
_MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
_MAX_INDEX_BYTES = 512 * 1024
_MAX_INSTRUCTION_BYTES = 32 * 1024
_EXPECTED_SELECTED_SKILLS = 4

_SNAPSHOT_PATH = "skill-bound-snapshot.json"
_INSTRUCTION_PROJECTION_PATH = "instruction-projection.json"
_EVIDENCE_PROJECTION_PATH = "evidence-projection.json"
_INDEX_PATH = "projection-index.json"
_ARTIFACT_LIMITS: Final = {
    _SNAPSHOT_PATH: _MAX_SNAPSHOT_BYTES,
    _INSTRUCTION_PROJECTION_PATH: _MAX_BUNDLE_BYTES,
    _EVIDENCE_PROJECTION_PATH: _MAX_BUNDLE_BYTES,
    _INDEX_PATH: _MAX_INDEX_BYTES,
}
_EXPECTED_ARTIFACTS: Final = frozenset(_ARTIFACT_LIMITS)
_STARTED_EVENT = "web-analysis.skill-projection.started"
_COMPLETED_EVENT = "web-analysis.skill-projection.completed"
_CAMPAIGN_NAME = "web-analysis-skill-projection"


def registered_web_pentest_exploit_group() -> ExploitGroupDefinition:
    """Resolve the code-owned AGENTIC-001 roster through the sole Skill consumer."""

    installed = built_in_proposal_analysis_skill_registry()
    installed_refs = {
        (reference.skill_id, reference.skill_version): AnalysisSkillReference.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
        for reference in installed.references()
    }
    return build_web_exploit_group(
        attack_path_skill_ref=installed_refs[(COMPOSE_WEB_ATTACK_PATH_SKILL_ID, "1.1.0")],
        authorization_skill_ref=installed_refs[(ASSESS_WEB_OBJECT_ACCESS_SKILL_ID, "1.1.0")],
        reporting_skill_ref=installed_refs[(WRITE_WEB_SECURITY_FINDING_SKILL_ID, "1.0.0")],
        sqli_skill_ref=installed_refs[(ASSESS_WEB_SQLI_SKILL_ID, "1.1.0")],
        xss_skill_ref=installed_refs[(ASSESS_WEB_XSS_SKILL_ID, "1.1.0")],
    )


class WebAnalysisSkillProjectionError(ValueError):
    """Raised when SKILL-002 preparation or strict verification fails closed."""


class _VerifiedSourceLoader(Protocol):
    def __call__(
        self,
        run_path: Path,
        *,
        expected_run_id: str,
        expected_root_digest: str,
    ) -> VerifiedAuthenticatedDiscoveryRun: ...


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Web analysis Skill authority markers must be literal false")
    return False


def _literal_true(value: object) -> Literal[True]:
    if type(value) is not bool or value is not True:
        raise ValueError("Web analysis Skill boundary markers must be literal true")
    return True


def _skill_digest(domain: str, value: object, *, max_bytes: int) -> str:
    from hashlib import sha256

    encoded = canonical_skill_json(value, label=domain)
    if len(encoded) > max_bytes:
        raise ValueError(f"{domain} exceeds the byte limit")
    domain_bytes = domain.encode("ascii")
    return sha256(
        b"PAJIN-WEB-ANALYSIS-SKILL\0"
        + len(domain_bytes).to_bytes(4, "big")
        + domain_bytes
        + len(encoded).to_bytes(8, "big")
        + encoded
    ).hexdigest()


def _projected_hypothesis_ids(projection: WebAnalysisModelProjection) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                hypothesis
                for diagnostic in projection.diagnostics
                for hypothesis in diagnostic.allowed_hypothesis_ids
            }
            | {
                hypothesis
                for path in projection.attack_paths
                for hypothesis in path.allowed_hypothesis_ids
            }
        )
    )


class WebAnalysisSkillProjectionBundle(StrictModel):
    """Two separately routed projections joined only by a local digest envelope."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-analysis-skill-projection-bundle/v1alpha1"] = Field(
        default=WEB_ANALYSIS_SKILL_PROJECTION_BUNDLE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebAnalysisSkillProjectionBundle"] = "WebAnalysisSkillProjectionBundle"
    bundle_id: str = Field(default="", alias="bundleId", max_length=110)
    bundle_digest: str = Field(default="", alias="bundleDigest", max_length=64)
    instruction_projection: AnalysisSkillInstructionProjection = Field(
        alias="instructionProjection"
    )
    evidence_projection: WebAnalysisModelProjection = Field(alias="evidenceProjection")
    instruction_message_role: Literal["developer"] = Field(alias="instructionMessageRole")
    evidence_message_role: Literal["user"] = Field(alias="evidenceMessageRole")
    projection_state: Literal["split-proposal-input-not-dispatched"] = Field(
        alias="projectionState"
    )
    selected_skill_instructions_code_owned: Literal[True] = Field(
        alias="selectedSkillInstructionsCodeOwned"
    )
    evidence_projection_tainted_untrusted: Literal[True] = Field(
        alias="evidenceProjectionTaintedUntrusted"
    )
    combined_user_message_authorized: Literal[False] = Field(alias="combinedUserMessageAuthorized")
    provider_dispatch_authorized: Literal[False] = Field(alias="providerDispatchAuthorized")
    scope_expansion_authority: Literal[False] = Field(alias="scopeExpansionAuthority")
    tool_request_authority: Literal[False] = Field(alias="toolRequestAuthority")
    capability_authority: Literal[False] = Field(alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(alias="permitAuthority")
    execution_authority: Literal[False] = Field(alias="executionAuthority")
    graph_admission_authority: Literal[False] = Field(alias="graphAdmissionAuthority")
    finding_authority: Literal[False] = Field(alias="findingAuthority")
    report_delivery_authority: Literal[False] = Field(alias="reportDeliveryAuthority")

    @field_validator(
        "selected_skill_instructions_code_owned",
        "evidence_projection_tainted_untrusted",
        mode="before",
    )
    @classmethod
    def require_true_markers(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @field_validator(
        "combined_user_message_authorized",
        "provider_dispatch_authorized",
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
    def bind_bundle(self) -> Self:
        instruction_projection = canonical_skill_contract(
            self.instruction_projection,
            AnalysisSkillInstructionProjection,
        )
        evidence_projection = canonical_skill_contract(
            self.evidence_projection,
            WebAnalysisModelProjection,
        )
        selected_hypotheses = tuple(
            sorted(
                {
                    hypothesis
                    for skill in instruction_projection.selected_skills
                    for hypothesis in skill.applicable_hypothesis_ids
                }
            )
        )
        if selected_hypotheses != _projected_hypothesis_ids(evidence_projection):
            raise ValueError("Selected Skill hypotheses differ from the evidence projection")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"bundle_id", "bundle_digest"},
        )
        digest = _skill_digest(
            "pajin.web-analysis.skill-projection-bundle/v1",
            material,
            max_bytes=_MAX_BUNDLE_BYTES,
        )
        bundle_id = f"web-analysis-skill-projection:{digest}"
        if self.bundle_digest and self.bundle_digest != digest:
            raise ValueError("Web analysis Skill projection bundle digest differs")
        if self.bundle_id and self.bundle_id != bundle_id:
            raise ValueError("Web analysis Skill projection bundle ID differs")
        object.__setattr__(self, "bundle_digest", digest)
        object.__setattr__(self, "bundle_id", bundle_id)
        return self


class SkillBoundWebAnalysisSnapshot(StrictModel):
    """Local exact binding of WEB-007 evidence to qualified selected Skill instructions."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-analysis-skill-bound-snapshot/v1alpha1"] = Field(
        default=WEB_ANALYSIS_SKILL_BOUND_SNAPSHOT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SkillBoundWebAnalysisSnapshot"] = "SkillBoundWebAnalysisSnapshot"
    snapshot_id: str = Field(default="", alias="snapshotId", max_length=110)
    snapshot_digest: str = Field(default="", alias="snapshotDigest", max_length=64)
    source_snapshot: WebAnalysisSnapshot = Field(alias="sourceSnapshot")
    qualification: ProposalOnlySkillQualificationSet
    selection_policy: AnalysisSkillSelectionPolicy = Field(alias="selectionPolicy")
    selection_receipt: AnalysisSkillSelectionReceipt = Field(alias="selectionReceipt")
    projection_bundle: WebAnalysisSkillProjectionBundle = Field(alias="projectionBundle")
    snapshot_state: Literal["skill-bound-proposal-input-not-dispatched"] = Field(
        alias="snapshotState"
    )
    model_invocation_performed: Literal[False] = Field(alias="modelInvocationPerformed")
    target_request_performed: Literal[False] = Field(alias="targetRequestPerformed")
    recipe_binding_created: Literal[False] = Field(alias="recipeBindingCreated")
    capability_granted: Literal[False] = Field(alias="capabilityGranted")
    permit_granted: Literal[False] = Field(alias="permitGranted")
    execution_authority: Literal[False] = Field(alias="executionAuthority")
    graph_admission_authority: Literal[False] = Field(alias="graphAdmissionAuthority")
    finding_authority: Literal[False] = Field(alias="findingAuthority")
    report_delivery_authority: Literal[False] = Field(alias="reportDeliveryAuthority")

    @field_validator(
        "model_invocation_performed",
        "target_request_performed",
        "recipe_binding_created",
        "capability_granted",
        "permit_granted",
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
        source_snapshot = canonical_skill_contract(self.source_snapshot, WebAnalysisSnapshot)
        qualification = canonical_skill_contract(
            self.qualification,
            ProposalOnlySkillQualificationSet,
        )
        selection_policy = canonical_skill_contract(
            self.selection_policy,
            AnalysisSkillSelectionPolicy,
        )
        selection_receipt = canonical_skill_contract(
            self.selection_receipt,
            AnalysisSkillSelectionReceipt,
        )
        projection_bundle = canonical_skill_contract(
            self.projection_bundle,
            WebAnalysisSkillProjectionBundle,
        )
        instruction_projection = projection_bundle.instruction_projection
        if (
            projection_bundle.evidence_projection != source_snapshot.model_projection
            or selection_policy.registry != qualification.qualified_registry
            or selection_receipt.registry != selection_policy.registry
            or instruction_projection.registry != selection_policy.registry
            or selection_policy.qualification_id != qualification.qualification_id
            or selection_policy.qualification_digest != qualification.qualification_digest
            or selection_receipt.qualification_id != qualification.qualification_id
            or selection_receipt.qualification_digest != qualification.qualification_digest
            or selection_receipt.policy_id != selection_policy.policy_id
            or selection_receipt.policy_digest != selection_policy.policy_digest
            or instruction_projection.qualification_id != qualification.qualification_id
            or instruction_projection.qualification_digest != qualification.qualification_digest
            or instruction_projection.policy_id != selection_policy.policy_id
            or instruction_projection.policy_digest != selection_policy.policy_digest
            or instruction_projection.selection_receipt_id != selection_receipt.receipt_id
            or instruction_projection.selection_receipt_digest != selection_receipt.receipt_digest
            or instruction_projection.selected_skill_count != selection_receipt.selected_skill_count
            or instruction_projection.projected_instruction_bytes
            != selection_receipt.projected_instruction_bytes
            or tuple(item.skill_ref for item in instruction_projection.selected_skills)
            != selection_receipt.selected_skill_refs
        ):
            raise ValueError("Skill-bound Web analysis Snapshot lineage differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"snapshot_id", "snapshot_digest"},
        )
        digest = _skill_digest(
            "pajin.web-analysis.skill-bound-snapshot/v1",
            material,
            max_bytes=_MAX_SNAPSHOT_BYTES,
        )
        snapshot_id = f"skill-bound-web-analysis:{digest}"
        if self.snapshot_digest and self.snapshot_digest != digest:
            raise ValueError("Skill-bound Web analysis Snapshot digest differs")
        if self.snapshot_id and self.snapshot_id != snapshot_id:
            raise ValueError("Skill-bound Web analysis Snapshot ID differs")
        object.__setattr__(self, "snapshot_digest", digest)
        object.__setattr__(self, "snapshot_id", snapshot_id)
        return self


class WebAnalysisSkillProjectionRunIndex(StrictModel):
    """Exact artifact and zero-dispatch accounting for one preparation Run."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-analysis-skill-projection-index/v1alpha1"] = Field(
        default=WEB_ANALYSIS_SKILL_PROJECTION_INDEX_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebAnalysisSkillProjectionRunIndex"] = "WebAnalysisSkillProjectionRunIndex"
    index_digest: str = Field(default="", alias="indexDigest", max_length=64)
    run_id: str = Field(alias="runId", pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    source_run_id: str = Field(alias="sourceRunId", pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_snapshot_id: str = Field(alias="sourceSnapshotId", min_length=1, max_length=110)
    source_snapshot_digest: _Sha256 = Field(alias="sourceSnapshotDigest")
    skill_bound_snapshot_id: str = Field(alias="skillBoundSnapshotId", min_length=1, max_length=110)
    skill_bound_snapshot_digest: _Sha256 = Field(alias="skillBoundSnapshotDigest")
    registry: SkillRegistryRef
    qualification_id: str = Field(alias="qualificationId", min_length=1, max_length=110)
    qualification_digest: _Sha256 = Field(alias="qualificationDigest")
    selection_policy_id: str = Field(alias="selectionPolicyId", min_length=1, max_length=110)
    selection_policy_digest: _Sha256 = Field(alias="selectionPolicyDigest")
    selection_receipt_id: str = Field(alias="selectionReceiptId", min_length=1, max_length=110)
    selection_receipt_digest: _Sha256 = Field(alias="selectionReceiptDigest")
    instruction_projection_id: str = Field(
        alias="instructionProjectionId", min_length=1, max_length=110
    )
    instruction_projection_digest: _Sha256 = Field(alias="instructionProjectionDigest")
    evidence_projection_id: str = Field(alias="evidenceProjectionId", min_length=1, max_length=110)
    evidence_projection_digest: _Sha256 = Field(alias="evidenceProjectionDigest")
    projection_bundle_id: str = Field(alias="projectionBundleId", min_length=1, max_length=110)
    projection_bundle_digest: _Sha256 = Field(alias="projectionBundleDigest")
    selected_skill_count: int = Field(alias="selectedSkillCount", strict=True, ge=1, le=32)
    projected_instruction_bytes: int = Field(
        alias="projectedInstructionBytes",
        strict=True,
        ge=1,
        le=_MAX_INSTRUCTION_BYTES,
    )
    started_at: datetime = Field(alias="startedAt")
    finished_at: datetime = Field(alias="finishedAt")
    semantics: Literal["proposal-only-skill-projection-no-dispatch"]
    model_invocation_count: Literal[0] = Field(alias="modelInvocationCount")
    provider_dispatch_count: Literal[0] = Field(alias="providerDispatchCount")
    target_request_count: Literal[0] = Field(alias="targetRequestCount")
    tool_request_count: Literal[0] = Field(alias="toolRequestCount")
    action_permit_count: Literal[0] = Field(alias="actionPermitCount")
    finding_count: Literal[0] = Field(alias="findingCount")
    graph_mutation_count: Literal[0] = Field(alias="graphMutationCount")
    external_delivery_performed: Literal[False] = Field(alias="externalDeliveryPerformed")
    execution_authority: Literal[False] = Field(alias="executionAuthority")
    finding_authority: Literal[False] = Field(alias="findingAuthority")
    graph_admission_authority: Literal[False] = Field(alias="graphAdmissionAuthority")

    @field_validator(
        "selected_skill_count",
        "projected_instruction_bytes",
        "model_invocation_count",
        "provider_dispatch_count",
        "target_request_count",
        "tool_request_count",
        "action_permit_count",
        "finding_count",
        "graph_mutation_count",
        mode="before",
    )
    @classmethod
    def require_integer_counts(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Web analysis Skill Run counts must use JSON integers")
        return value

    @field_validator(
        "external_delivery_performed",
        "execution_authority",
        "finding_authority",
        "graph_admission_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_index(self) -> Self:
        if self.started_at.tzinfo is None or self.finished_at.tzinfo is None:
            raise ValueError("Web analysis Skill Run timestamps must be timezone-aware")
        if self.finished_at < self.started_at:
            raise ValueError("Web analysis Skill Run finished before it started")
        material = self.model_dump(mode="json", by_alias=True, exclude={"index_digest"})
        digest = _skill_digest(
            "pajin.web-analysis.skill-projection-index/v1",
            material,
            max_bytes=_MAX_INDEX_BYTES,
        )
        if self.index_digest and self.index_digest != digest:
            raise ValueError("Web analysis Skill projection Index digest differs")
        object.__setattr__(self, "index_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class VerifiedWebAnalysisSkillProjectionRun:
    """Strictly reloaded SKILL-002 preparation with independent anchors."""

    run_path: Path
    verification: RunIntegrityVerification
    snapshot: SkillBoundWebAnalysisSnapshot
    instruction_projection: AnalysisSkillInstructionProjection
    evidence_projection: WebAnalysisModelProjection
    index: WebAnalysisSkillProjectionRunIndex
    semantics: Literal["proposal-only-skill-projection-no-dispatch"] = (
        "proposal-only-skill-projection-no-dispatch"
    )
    model_invocation_performed: Literal[False] = False
    execution_authority: Literal[False] = False


def registered_web_analysis_skill_selection_policy(
    *,
    source_projection: WebAnalysisModelProjection,
    qualified_registry_ref: SkillRegistryRef,
    qualification: ProposalOnlySkillQualificationSet,
) -> AnalysisSkillSelectionPolicy:
    """Return the only installed WEB-007 pre-execution Skill selection policy."""

    source_projection = canonical_skill_contract(
        source_projection,
        WebAnalysisModelProjection,
    )
    qualification = canonical_skill_contract(
        qualification,
        ProposalOnlySkillQualificationSet,
    )
    qualified_registry_ref = canonical_skill_contract(qualified_registry_ref, SkillRegistryRef)
    registry = resolve_installed_analysis_skill_registry(qualified_registry_ref)
    installed = built_in_proposal_analysis_skill_registry()
    if (
        registry.reference() != installed.reference()
        or registry.reference() != qualified_registry_ref
    ):
        raise WebAnalysisSkillProjectionError("Web Skill registry is not the installed successor")
    expected_qualification = qualify_proposal_only_skill_registry(
        predecessor_registry=built_in_analysis_skill_registry(),
        qualified_registry=installed,
    )
    if qualification != expected_qualification:
        raise WebAnalysisSkillProjectionError("Web Skill qualification differs from code authority")
    allowed_refs = tuple(item.qualified for item in qualification.bindings)
    definitions = tuple(registry.resolve(reference).definition for reference in allowed_refs)
    domain = definitions[0].domain_classifications[0]
    if any(
        definition.lifecycle_stage is not SkillLifecycleStage.PROPOSAL_ONLY
        or definition.domain_classifications != (domain,)
        for definition in definitions
    ):
        raise WebAnalysisSkillProjectionError("Web Skill selection metadata differs")
    return AnalysisSkillSelectionPolicy(
        policyId="",
        policyDigest="",
        registry=registry.reference(),
        qualificationId=qualification.qualification_id,
        qualificationDigest=qualification.qualification_digest,
        allowedSkillRefs=allowed_refs,
        agentRole=AgentRole.PLANNER,
        domainClassification=domain,
        surfaceType="web.http-operation",
        allowedHypothesisIds=_projected_hypothesis_ids(source_projection),
        maxSelectedSkills=_EXPECTED_SELECTED_SKILLS,
        maxProjectedInstructionBytes=_MAX_INSTRUCTION_BYTES,
        selectionBasis="code-owned-metadata-intersection",
        targetContentUsedForSelection=False,
        modelSelectedSkills=False,
        scopeExpansionAuthority=False,
        recipeBindingAuthority=False,
        capabilityAuthority=False,
        permitAuthority=False,
        executionAuthority=False,
    )


def build_skill_bound_web_analysis_snapshot(
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    expected_source_run_id: str,
    expected_source_root_digest: str,
) -> SkillBoundWebAnalysisSnapshot:
    """Build one exact SKILL-002 snapshot through the production sealed source loader."""

    try:
        source_snapshot = build_web_analysis_snapshot(
            source,
            expected_run_id=expected_source_run_id,
            expected_root_digest=expected_source_root_digest,
        )
        return _bind_skill_snapshot(source_snapshot)
    except Exception as exc:
        if isinstance(exc, WebAnalysisSkillProjectionError):
            raise
        raise WebAnalysisSkillProjectionError(
            "Skill-bound Web analysis Snapshot construction failed closed"
        ) from exc


def _build_skill_bound_web_analysis_snapshot_with_loader(
    source: VerifiedAuthenticatedDiscoveryRun,
    *,
    source_loader: _VerifiedSourceLoader,
    expected_source_run_id: str,
    expected_source_root_digest: str,
) -> SkillBoundWebAnalysisSnapshot:
    source_snapshot = _build_web_analysis_snapshot_with_loader(
        source,
        source_loader=source_loader,
        expected_run_id=expected_source_run_id,
        expected_root_digest=expected_source_root_digest,
    )
    return _bind_skill_snapshot(source_snapshot)


def _bind_skill_snapshot(source_snapshot: WebAnalysisSnapshot) -> SkillBoundWebAnalysisSnapshot:
    predecessor_registry = built_in_analysis_skill_registry()
    registry = built_in_proposal_analysis_skill_registry()
    qualification = qualify_proposal_only_skill_registry(
        predecessor_registry=predecessor_registry,
        qualified_registry=registry,
    )
    policy = registered_web_analysis_skill_selection_policy(
        source_projection=source_snapshot.model_projection,
        qualified_registry_ref=registry.reference(),
        qualification=qualification,
    )
    receipt, _selected = select_analysis_skills_from_code_owned_policy(
        registry=registry,
        qualification=qualification,
        policy=policy,
    )
    instruction_projection = build_analysis_skill_instruction_projection_from_code_owned_policy(
        registry=registry,
        qualification=qualification,
        policy=policy,
        receipt=receipt,
    )
    bundle = WebAnalysisSkillProjectionBundle(
        bundleId="",
        bundleDigest="",
        instructionProjection=instruction_projection,
        evidenceProjection=source_snapshot.model_projection,
        instructionMessageRole="developer",
        evidenceMessageRole="user",
        projectionState="split-proposal-input-not-dispatched",
        selectedSkillInstructionsCodeOwned=True,
        evidenceProjectionTaintedUntrusted=True,
        combinedUserMessageAuthorized=False,
        providerDispatchAuthorized=False,
        scopeExpansionAuthority=False,
        toolRequestAuthority=False,
        capabilityAuthority=False,
        permitAuthority=False,
        executionAuthority=False,
        graphAdmissionAuthority=False,
        findingAuthority=False,
        reportDeliveryAuthority=False,
    )
    return SkillBoundWebAnalysisSnapshot(
        snapshotId="",
        snapshotDigest="",
        sourceSnapshot=source_snapshot,
        qualification=qualification,
        selectionPolicy=policy,
        selectionReceipt=receipt,
        projectionBundle=bundle,
        snapshotState="skill-bound-proposal-input-not-dispatched",
        modelInvocationPerformed=False,
        targetRequestPerformed=False,
        recipeBindingCreated=False,
        capabilityGranted=False,
        permitGranted=False,
        executionAuthority=False,
        graphAdmissionAuthority=False,
        findingAuthority=False,
        reportDeliveryAuthority=False,
    )


def create_web_analysis_skill_projection_run(
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    output_root: Path,
) -> VerifiedWebAnalysisSkillProjectionRun:
    """Seal and immediately strict-reload one zero-dispatch SKILL-002 preparation Run."""

    return _create_web_analysis_skill_projection_run_with_loader(
        source=source,
        expected_source_run_id=expected_source_run_id,
        expected_source_root_digest=expected_source_root_digest,
        output_root=output_root,
        source_loader=load_verified_authenticated_discovery,
    )


def _create_web_analysis_skill_projection_run_with_loader(
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    output_root: Path,
    source_loader: _VerifiedSourceLoader,
) -> VerifiedWebAnalysisSkillProjectionRun:
    try:
        snapshot = _build_skill_bound_web_analysis_snapshot_with_loader(
            source,
            source_loader=source_loader,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
        )
        started_at = datetime.now(UTC)
        finished_at = datetime.now(UTC)
        run_id = RunStore.new_run_id()
        instruction = snapshot.projection_bundle.instruction_projection
        evidence = snapshot.projection_bundle.evidence_projection
        index = WebAnalysisSkillProjectionRunIndex(
            indexDigest="",
            runId=run_id,
            sourceRunId=source.verification.run_id,
            sourceRootDigest=source.verification.root_digest,
            sourceSnapshotId=snapshot.source_snapshot.snapshot_id,
            sourceSnapshotDigest=snapshot.source_snapshot.snapshot_digest,
            skillBoundSnapshotId=snapshot.snapshot_id,
            skillBoundSnapshotDigest=snapshot.snapshot_digest,
            registry=snapshot.selection_policy.registry,
            qualificationId=snapshot.qualification.qualification_id,
            qualificationDigest=snapshot.qualification.qualification_digest,
            selectionPolicyId=snapshot.selection_policy.policy_id,
            selectionPolicyDigest=snapshot.selection_policy.policy_digest,
            selectionReceiptId=snapshot.selection_receipt.receipt_id,
            selectionReceiptDigest=snapshot.selection_receipt.receipt_digest,
            instructionProjectionId=instruction.projection_id,
            instructionProjectionDigest=instruction.projection_digest,
            evidenceProjectionId=evidence.projection_id,
            evidenceProjectionDigest=evidence.projection_digest,
            projectionBundleId=snapshot.projection_bundle.bundle_id,
            projectionBundleDigest=snapshot.projection_bundle.bundle_digest,
            selectedSkillCount=instruction.selected_skill_count,
            projectedInstructionBytes=instruction.projected_instruction_bytes,
            startedAt=started_at,
            finishedAt=finished_at,
            semantics="proposal-only-skill-projection-no-dispatch",
            modelInvocationCount=0,
            providerDispatchCount=0,
            targetRequestCount=0,
            toolRequestCount=0,
            actionPermitCount=0,
            findingCount=0,
            graphMutationCount=0,
            externalDeliveryPerformed=False,
            executionAuthority=False,
            findingAuthority=False,
            graphAdmissionAuthority=False,
        )
        store = RunStore.create(output_root, _CAMPAIGN_NAME, run_id=run_id)
        store.append_event(
            _STARTED_EVENT,
            _started_event_payload(snapshot),
            occurred_at=started_at,
        )
        for path, artifact in (
            (_SNAPSHOT_PATH, snapshot),
            (_INSTRUCTION_PROJECTION_PATH, instruction),
            (_EVIDENCE_PROJECTION_PATH, evidence),
            (_INDEX_PATH, index),
        ):
            store.write_json_create_only(
                path,
                artifact.model_dump(mode="json", by_alias=True, exclude_none=True),
            )
        store.append_event(
            _COMPLETED_EVENT,
            _completed_event_payload(index),
            occurred_at=finished_at,
        )
        seal = store.seal()
        verification = verify_run_integrity(store.path)
        if verification.root_digest != seal.root_digest:
            raise ValueError("Web analysis Skill Run seal verification differs")
        return _load_verified_web_analysis_skill_projection_with_loader(
            store.path,
            source=source,
            expected_run_id=run_id,
            expected_root_digest=seal.root_digest,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_registry_ref=snapshot.selection_policy.registry,
            expected_policy_digest=snapshot.selection_policy.policy_digest,
            source_loader=source_loader,
        )
    except Exception as exc:
        if isinstance(exc, WebAnalysisSkillProjectionError):
            raise
        raise WebAnalysisSkillProjectionError(
            "Web analysis Skill projection Run failed closed"
        ) from exc


def load_verified_web_analysis_skill_projection(
    run_path: Path,
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    expected_run_id: str,
    expected_root_digest: str,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_registry_ref: SkillRegistryRef,
    expected_policy_digest: str,
) -> VerifiedWebAnalysisSkillProjectionRun:
    """Reload a Run under independent Run, source, registry, and policy anchors."""

    return _load_verified_web_analysis_skill_projection_with_loader(
        run_path,
        source=source,
        expected_run_id=expected_run_id,
        expected_root_digest=expected_root_digest,
        expected_source_run_id=expected_source_run_id,
        expected_source_root_digest=expected_source_root_digest,
        expected_registry_ref=expected_registry_ref,
        expected_policy_digest=expected_policy_digest,
        source_loader=load_verified_authenticated_discovery,
    )


def _load_verified_web_analysis_skill_projection_with_loader(
    run_path: Path,
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    expected_run_id: str,
    expected_root_digest: str,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_registry_ref: SkillRegistryRef,
    expected_policy_digest: str,
    source_loader: _VerifiedSourceLoader,
) -> VerifiedWebAnalysisSkillProjectionRun:
    try:
        _require_external_anchors(
            expected_run_id=expected_run_id,
            expected_root_digest=expected_root_digest,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            expected_policy_digest=expected_policy_digest,
        )
        resolve_installed_analysis_skill_registry(expected_registry_ref)
        initial = load_verified_run_snapshot(run_path, expected_run_id=expected_run_id)
        _require_run_shape(initial, expected_root_digest=expected_root_digest)
        loaded = load_verified_run_artifacts(
            initial.run_path,
            requests=dict(_ARTIFACT_LIMITS),
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            loaded,
            message="sealed Web analysis Skill Run changed while artifacts were loaded",
        )
        snapshot = _strict_artifact_model(loaded, _SNAPSHOT_PATH, SkillBoundWebAnalysisSnapshot)
        instruction = _strict_artifact_model(
            loaded,
            _INSTRUCTION_PROJECTION_PATH,
            AnalysisSkillInstructionProjection,
        )
        evidence = _strict_artifact_model(
            loaded,
            _EVIDENCE_PROJECTION_PATH,
            WebAnalysisModelProjection,
        )
        index = _strict_artifact_model(
            loaded,
            _INDEX_PATH,
            WebAnalysisSkillProjectionRunIndex,
        )
        expected_snapshot = _build_skill_bound_web_analysis_snapshot_with_loader(
            source,
            source_loader=source_loader,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
        )
        if (
            expected_registry_ref != expected_snapshot.selection_policy.registry
            or expected_policy_digest != expected_snapshot.selection_policy.policy_digest
            or snapshot != expected_snapshot
            or instruction != snapshot.projection_bundle.instruction_projection
            or evidence != snapshot.projection_bundle.evidence_projection
        ):
            raise ValueError("Web analysis Skill projection differs from external authority")
        _require_index_and_events(
            loaded,
            skill_snapshot=snapshot,
            instruction=instruction,
            evidence=evidence,
            index=index,
        )
        final = load_verified_run_snapshot(initial.run_path, expected_run_id=expected_run_id)
        require_same_authority(
            loaded,
            final,
            message="sealed Web analysis Skill Run changed after verification",
        )
        return VerifiedWebAnalysisSkillProjectionRun(
            run_path=final.run_path,
            verification=final.verification,
            snapshot=snapshot,
            instruction_projection=instruction,
            evidence_projection=evidence,
            index=index,
        )
    except Exception as exc:
        if isinstance(exc, WebAnalysisSkillProjectionError):
            raise
        raise WebAnalysisSkillProjectionError(
            "sealed Web analysis Skill projection verification failed closed"
        ) from exc


def _artifact_records(snapshot: VerifiedRunSnapshot) -> dict[str, SealedArtifact]:
    records = {artifact.path: artifact for seal in snapshot.seals for artifact in seal.artifacts}
    if len(records) != sum(len(seal.artifacts) for seal in snapshot.seals):
        raise ValueError("Web analysis Skill Run contains duplicate artifact paths")
    return records


def _require_run_shape(snapshot: VerifiedRunSnapshot, *, expected_root_digest: str) -> None:
    records = _artifact_records(snapshot)
    if (
        snapshot.verification.root_digest != expected_root_digest
        or snapshot.verification.seal_count != 1
        or snapshot.verification.event_count != 2
        or snapshot.verification.artifact_count != len(_EXPECTED_ARTIFACTS)
        or len(snapshot.seals) != 1
        or tuple(event.event_type for event in snapshot.events)
        != (_STARTED_EVENT, _COMPLETED_EVENT)
        or set(records) != _EXPECTED_ARTIFACTS
    ):
        raise ValueError("sealed Web analysis Skill Run shape differs")
    for path, record in records.items():
        if (
            record.media_type != "application/json"
            or record.size_bytes < 1
            or record.size_bytes > _ARTIFACT_LIMITS[path]
        ):
            raise ValueError(f"Web analysis Skill artifact boundary differs: {path}")


def _strict_artifact_model[T: BaseModel](
    snapshot: VerifiedRunSnapshot,
    path: str,
    model: type[T],
) -> T:
    raw = strict_json(
        snapshot,
        path,
        label=f"Web analysis Skill {path}",
        max_bytes=_ARTIFACT_LIMITS[path],
        expected_type=dict,
    )
    value = model.model_validate(raw)
    if raw != value.model_dump(mode="json", by_alias=True, exclude_none=True):
        raise ValueError(f"Web analysis Skill {path} is not canonical")
    return value


def _require_index_and_events(
    run_snapshot: VerifiedRunSnapshot,
    *,
    skill_snapshot: SkillBoundWebAnalysisSnapshot,
    instruction: AnalysisSkillInstructionProjection,
    evidence: WebAnalysisModelProjection,
    index: WebAnalysisSkillProjectionRunIndex,
) -> None:
    source_snapshot = skill_snapshot.source_snapshot
    qualification = skill_snapshot.qualification
    policy = skill_snapshot.selection_policy
    receipt = skill_snapshot.selection_receipt
    bundle = skill_snapshot.projection_bundle
    if (
        index.run_id != run_snapshot.verification.run_id
        or index.source_run_id != source_snapshot.source_run_id
        or index.source_root_digest != source_snapshot.source_root_digest
        or index.source_snapshot_id != source_snapshot.snapshot_id
        or index.source_snapshot_digest != source_snapshot.snapshot_digest
        or index.skill_bound_snapshot_id != skill_snapshot.snapshot_id
        or index.skill_bound_snapshot_digest != skill_snapshot.snapshot_digest
        or index.registry != policy.registry
        or index.qualification_id != qualification.qualification_id
        or index.qualification_digest != qualification.qualification_digest
        or index.selection_policy_id != policy.policy_id
        or index.selection_policy_digest != policy.policy_digest
        or index.selection_receipt_id != receipt.receipt_id
        or index.selection_receipt_digest != receipt.receipt_digest
        or index.instruction_projection_id != instruction.projection_id
        or index.instruction_projection_digest != instruction.projection_digest
        or index.evidence_projection_id != evidence.projection_id
        or index.evidence_projection_digest != evidence.projection_digest
        or index.projection_bundle_id != bundle.bundle_id
        or index.projection_bundle_digest != bundle.bundle_digest
        or index.selected_skill_count != instruction.selected_skill_count
        or index.projected_instruction_bytes != instruction.projected_instruction_bytes
    ):
        raise ValueError("Web analysis Skill Run Index bindings differ")
    started, completed = run_snapshot.events
    if (
        started.occurred_at != index.started_at
        or started.payload != _started_event_payload(skill_snapshot)
        or completed.occurred_at != index.finished_at
        or completed.payload != _completed_event_payload(index)
    ):
        raise ValueError("Web analysis Skill Run events differ from its Index")


def _started_event_payload(snapshot: SkillBoundWebAnalysisSnapshot) -> dict[str, object]:
    return {
        "evidenceProjectionDigest": (
            snapshot.projection_bundle.evidence_projection.projection_digest
        ),
        "instructionProjectionDigest": (
            snapshot.projection_bundle.instruction_projection.projection_digest
        ),
        "registryDigest": snapshot.selection_policy.registry.registry_digest,
        "selectionPolicyDigest": snapshot.selection_policy.policy_digest,
        "semantics": "proposal-only-skill-projection-no-dispatch",
        "sourceSnapshotDigest": snapshot.source_snapshot.snapshot_digest,
    }


def _completed_event_payload(index: WebAnalysisSkillProjectionRunIndex) -> dict[str, object]:
    return {
        "indexDigest": index.index_digest,
        "modelInvocationCount": 0,
        "projectionBundleDigest": index.projection_bundle_digest,
        "providerDispatchCount": 0,
        "selectedSkillCount": index.selected_skill_count,
        "semantics": "proposal-only-skill-projection-no-dispatch",
        "targetRequestCount": 0,
    }


def _require_external_anchors(
    *,
    expected_run_id: str,
    expected_root_digest: str,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_policy_digest: str,
) -> None:
    if (
        _RUN_ID_PATTERN.fullmatch(expected_run_id) is None
        or _RUN_ID_PATTERN.fullmatch(expected_source_run_id) is None
        or _SHA256_PATTERN.fullmatch(expected_root_digest) is None
        or _SHA256_PATTERN.fullmatch(expected_source_root_digest) is None
        or _SHA256_PATTERN.fullmatch(expected_policy_digest) is None
    ):
        raise ValueError("Web analysis Skill external anchors are invalid")


__all__ = [
    "WEB_ANALYSIS_SKILL_BOUND_SNAPSHOT_API_VERSION",
    "WEB_ANALYSIS_SKILL_PROJECTION_BUNDLE_API_VERSION",
    "WEB_ANALYSIS_SKILL_PROJECTION_INDEX_API_VERSION",
    "SkillBoundWebAnalysisSnapshot",
    "SkillRegistryRef",
    "VerifiedWebAnalysisSkillProjectionRun",
    "WebAnalysisSkillProjectionBundle",
    "WebAnalysisSkillProjectionError",
    "WebAnalysisSkillProjectionRunIndex",
    "build_skill_bound_web_analysis_snapshot",
    "canonical_skill_contract",
    "create_web_analysis_skill_projection_run",
    "load_verified_web_analysis_skill_projection",
    "registered_web_analysis_skill_selection_policy",
    "registered_web_pentest_exploit_group",
]
