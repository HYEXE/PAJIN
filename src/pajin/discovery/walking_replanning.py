"""Evidence-bound Observation admission and non-executable replanning for WALK-004."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from re import fullmatch
from typing import Literal, cast

from pydantic import Field, JsonValue, field_validator, model_validator

from pajin.capabilities.models import CapabilityDefinitionRef
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.walking import _campaign_digest, _safe_text
from pajin.discovery.walking_mcp import (
    MCPToolAuthorizationHypothesisAuthority,
    MCPToolAuthorizationHypothesisOutcome,
)
from pajin.domain.models import CampaignManifest, StrictModel, campaign_manifest_digest
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

WALKING_OBSERVATION_REPLAN_API_VERSION: Literal["pajin.dev/walking-observation-replan/v1alpha1"] = (
    "pajin.dev/walking-observation-replan/v1alpha1"
)

WalkingGraphRelation = Literal["supports", "contradicts", "enables", "depends-on"]
WalkingGraphNodeKind = Literal["hypothesis", "observation", "plan"]

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_EVIDENCE_ID_PATTERN = r"^walking-observation-evidence_[a-f0-9]{64}$"
_OBSERVATION_ID_PATTERN = r"^walking-observation_[a-f0-9]{64}$"
_PLAN_ID_PATTERN = r"^walking-replan_[a-f0-9]{64}$"
_RELATIONSHIP_ID_PATTERN = r"^walking-relationship_[a-f0-9]{64}$"
_GRAPH_ID_PATTERN = r"^walking-observation-graph_[a-f0-9]{64}$"
_AUTHORITY_ID_PATTERN = r"^walking-observation-replan_[a-f0-9]{64}$"
_MAX_AUTHORITY_BYTES = 1_048_576


class WalkingObservationReplanError(RuntimeError):
    """Raised when WALK-004 cannot prove an exact bounded Replan authority."""


class RegisteredWalkingObservationReplanRule(StrictModel):
    """Code-owned admission and Replan mapping for one WALK-003 rule."""

    rule_id: str = Field(alias="ruleId", pattern=_IDENTIFIER_PATTERN)
    source_hypothesis_rule_id: str = Field(
        alias="sourceHypothesisRuleId",
        pattern=_IDENTIFIER_PATTERN,
    )
    observed_execution_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="observedExecutionState",
    )
    observation_kind: Literal["independent-approval-required"] = Field(
        default="independent-approval-required",
        alias="observationKind",
    )
    next_action: Literal["request-independent-approval"] = Field(
        default="request-independent-approval",
        alias="nextAction",
    )
    support_relation: Literal["supports"] = Field(default="supports", alias="supportRelation")
    enable_relation: Literal["enables"] = Field(default="enables", alias="enableRelation")
    dependency_relation: Literal["depends-on"] = Field(
        default="depends-on",
        alias="dependencyRelation",
    )
    rationale: str = Field(min_length=1, max_length=2_000)

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, value: str) -> str:
        return _safe_text(value, label="Walking Observation Replan rationale")

    @property
    def rule_digest(self) -> str:
        return discovery_digest(
            "pajin.walking.observation-replan-rule/v1",
            self.model_dump(mode="json", by_alias=True),
        )


def walking_observation_replan_rule(
    *,
    source_hypothesis_rule_id: str,
) -> RegisteredWalkingObservationReplanRule:
    """Return the code-registered WALK-004 baseline for one WALK-003 authority."""

    return RegisteredWalkingObservationReplanRule(
        ruleId="pajin.walk.mcp-authorization-observation-replan.v1",
        sourceHypothesisRuleId=source_hypothesis_rule_id,
        rationale=(
            "A sealed registered-not-authorized MCP hypothesis permits only a bounded plan to "
            "request the already-required independent approval; it does not permit invocation."
        ),
    )


class SealedMCPAuthorizationHypothesisDependency(StrictModel):
    """Complete verified WALK-003 publication lineage consumed by WALK-004."""

    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    root_digest: str = Field(alias="rootDigest", pattern=_SHA256_PATTERN)
    artifact_path: str = Field(alias="artifactPath", min_length=1, max_length=2_000)
    artifact_sha256: str = Field(alias="artifactSha256", pattern=_SHA256_PATTERN)
    hypothesis: MCPToolAuthorizationHypothesisAuthority


class MCPAuthorizationObservationEvidence(StrictModel):
    """Untrusted candidate identity that must exactly match sealed WALK-003 evidence."""

    evidence_id: str = Field(default="", alias="evidenceId")
    evidence_digest: str = Field(default="", alias="evidenceDigest")
    evidence_kind: Literal["sealed-hypothesis-state"] = Field(
        default="sealed-hypothesis-state",
        alias="evidenceKind",
    )
    campaign: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")
    campaign_digest: str = Field(alias="campaignDigest", pattern=_SHA256_PATTERN)
    source_run_id: str = Field(alias="sourceRunId", min_length=1, max_length=200)
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=_SHA256_PATTERN)
    source_artifact_path: str = Field(
        alias="sourceArtifactPath",
        min_length=1,
        max_length=2_000,
    )
    source_artifact_sha256: str = Field(alias="sourceArtifactSha256", pattern=_SHA256_PATTERN)
    hypothesis_id: str = Field(alias="hypothesisId", min_length=1, max_length=200)
    hypothesis_digest: str = Field(alias="hypothesisDigest", pattern=_SHA256_PATTERN)
    observed_execution_state: Literal["registered-not-authorized"] = Field(
        alias="observedExecutionState"
    )

    @model_validator(mode="after")
    def validate_identity(self) -> MCPAuthorizationObservationEvidence:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evidence_id", "evidence_digest"},
        )
        digest = discovery_digest("pajin.walking.observation-evidence/v1", material)
        evidence_id = f"walking-observation-evidence_{digest}"
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("Walking Observation evidence Digest differs")
        if self.evidence_id and self.evidence_id != evidence_id:
            raise ValueError("Walking Observation evidence ID differs")
        self.evidence_digest = digest
        self.evidence_id = evidence_id
        if fullmatch(_EVIDENCE_ID_PATTERN, self.evidence_id) is None:
            raise ValueError("Walking Observation evidence ID is malformed")
        return self


class AdmittedMCPAuthorizationObservation(StrictModel):
    """Evidence-bound admission; free-form text never becomes Plan authority."""

    observation_id: str = Field(default="", alias="observationId")
    observation_digest: str = Field(default="", alias="observationDigest")
    campaign: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")
    campaign_digest: str = Field(alias="campaignDigest", pattern=_SHA256_PATTERN)
    evidence: MCPAuthorizationObservationEvidence
    rule_id: str = Field(alias="ruleId", pattern=_IDENTIFIER_PATTERN)
    rule_digest: str = Field(alias="ruleDigest", pattern=_SHA256_PATTERN)
    hypothesis_id: str = Field(alias="hypothesisId", min_length=1, max_length=200)
    hypothesis_digest: str = Field(alias="hypothesisDigest", pattern=_SHA256_PATTERN)
    observation_kind: Literal["independent-approval-required"] = Field(alias="observationKind")
    observed_execution_state: Literal["registered-not-authorized"] = Field(
        alias="observedExecutionState"
    )
    admission_state: Literal["admitted"] = Field(default="admitted", alias="admissionState")

    @model_validator(mode="after")
    def validate_identity(self) -> AdmittedMCPAuthorizationObservation:
        if (
            self.evidence.campaign != self.campaign
            or self.evidence.campaign_digest != self.campaign_digest
            or self.evidence.hypothesis_id != self.hypothesis_id
            or self.evidence.hypothesis_digest != self.hypothesis_digest
            or self.evidence.observed_execution_state != self.observed_execution_state
        ):
            raise ValueError("Walking Observation differs from its admitted evidence")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"observation_id", "observation_digest"},
        )
        digest = discovery_digest("pajin.walking.admitted-observation/v1", material)
        observation_id = f"walking-observation_{digest}"
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("Walking Observation Digest differs")
        if self.observation_id and self.observation_id != observation_id:
            raise ValueError("Walking Observation ID differs")
        self.observation_digest = digest
        self.observation_id = observation_id
        if fullmatch(_OBSERVATION_ID_PATTERN, self.observation_id) is None:
            raise ValueError("Walking Observation ID is malformed")
        return self


class WalkingFollowUpPlan(StrictModel):
    """A non-executable Plan selected by one admitted Observation."""

    plan_id: str = Field(default="", alias="planId")
    plan_digest: str = Field(default="", alias="planDigest")
    plan_state_digest: str = Field(default="", alias="planStateDigest")
    campaign: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")
    campaign_digest: str = Field(alias="campaignDigest", pattern=_SHA256_PATTERN)
    previous_state_digest: str = Field(alias="previousStateDigest", pattern=_SHA256_PATTERN)
    observation_id: str = Field(alias="observationId", min_length=1, max_length=200)
    observation_digest: str = Field(alias="observationDigest", pattern=_SHA256_PATTERN)
    hypothesis_id: str = Field(alias="hypothesisId", min_length=1, max_length=200)
    hypothesis_digest: str = Field(alias="hypothesisDigest", pattern=_SHA256_PATTERN)
    rag_surface_snapshot_id: str = Field(
        alias="ragSurfaceSnapshotId",
        min_length=1,
        max_length=200,
    )
    rag_surface_snapshot_digest: str = Field(
        alias="ragSurfaceSnapshotDigest",
        pattern=_SHA256_PATTERN,
    )
    mcp_surface_snapshot_id: str = Field(
        alias="mcpSurfaceSnapshotId",
        min_length=1,
        max_length=200,
    )
    mcp_surface_snapshot_digest: str = Field(
        alias="mcpSurfaceSnapshotDigest",
        pattern=_SHA256_PATTERN,
    )
    required_capability: CapabilityDefinitionRef = Field(alias="requiredCapability")
    authorization_control: Literal["independent-user-approval"] = Field(
        alias="authorizationControl"
    )
    action: Literal["request-independent-approval"]
    execution_state: Literal["proposed-not-authorized"] = Field(
        default="proposed-not-authorized",
        alias="executionState",
    )

    @model_validator(mode="after")
    def validate_identity(self) -> WalkingFollowUpPlan:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_id", "plan_digest", "plan_state_digest"},
        )
        state_material = dict(material)
        state_material.pop("previousStateDigest")
        state_digest = discovery_digest("pajin.walking.replan-state/v1", state_material)
        identity_material = {**material, "planStateDigest": state_digest}
        digest = discovery_digest("pajin.walking.follow-up-plan/v1", identity_material)
        plan_id = f"walking-replan_{digest}"
        if self.plan_state_digest and self.plan_state_digest != state_digest:
            raise ValueError("Walking Replan state Digest differs")
        if self.plan_digest and self.plan_digest != digest:
            raise ValueError("Walking Replan Digest differs")
        if self.plan_id and self.plan_id != plan_id:
            raise ValueError("Walking Replan ID differs")
        self.plan_state_digest = state_digest
        self.plan_digest = digest
        self.plan_id = plan_id
        if fullmatch(_PLAN_ID_PATTERN, self.plan_id) is None:
            raise ValueError("Walking Replan ID is malformed")
        return self


class WalkingGraphRelationship(StrictModel):
    """Typed relationship in the WALK-004 Graph snapshot."""

    relationship_id: str = Field(default="", alias="relationshipId")
    relationship_digest: str = Field(default="", alias="relationshipDigest")
    source_kind: WalkingGraphNodeKind = Field(alias="sourceKind")
    source_id: str = Field(alias="sourceId", min_length=1, max_length=200)
    relation: WalkingGraphRelation
    target_kind: WalkingGraphNodeKind = Field(alias="targetKind")
    target_id: str = Field(alias="targetId", min_length=1, max_length=200)
    rule_id: str = Field(alias="ruleId", pattern=_IDENTIFIER_PATTERN)
    rule_digest: str = Field(alias="ruleDigest", pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_identity(self) -> WalkingGraphRelationship:
        if self.source_kind == self.target_kind and self.source_id == self.target_id:
            raise ValueError("Walking Graph relationship cannot be a self-edge")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"relationship_id", "relationship_digest"},
        )
        digest = discovery_digest("pajin.walking.graph-relationship/v1", material)
        relationship_id = f"walking-relationship_{digest}"
        if self.relationship_digest and self.relationship_digest != digest:
            raise ValueError("Walking Graph Relationship Digest differs")
        if self.relationship_id and self.relationship_id != relationship_id:
            raise ValueError("Walking Graph Relationship ID differs")
        self.relationship_digest = digest
        self.relationship_id = relationship_id
        if fullmatch(_RELATIONSHIP_ID_PATTERN, self.relationship_id) is None:
            raise ValueError("Walking Graph Relationship ID is malformed")
        return self


class WalkingObservationGraphSnapshot(StrictModel):
    """Immutable WALK-004 Graph projection for one admitted transition."""

    snapshot_id: str = Field(default="", alias="snapshotId")
    snapshot_digest: str = Field(default="", alias="snapshotDigest")
    revision: Literal[1] = 1
    campaign: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")
    campaign_digest: str = Field(alias="campaignDigest", pattern=_SHA256_PATTERN)
    source_run_id: str = Field(alias="sourceRunId", min_length=1, max_length=200)
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=_SHA256_PATTERN)
    hypothesis_id: str = Field(alias="hypothesisId", min_length=1, max_length=200)
    hypothesis_digest: str = Field(alias="hypothesisDigest", pattern=_SHA256_PATTERN)
    observation_id: str = Field(alias="observationId", min_length=1, max_length=200)
    observation_digest: str = Field(alias="observationDigest", pattern=_SHA256_PATTERN)
    plan_id: str = Field(alias="planId", min_length=1, max_length=200)
    plan_digest: str = Field(alias="planDigest", pattern=_SHA256_PATTERN)
    previous_state_digest: str = Field(alias="previousStateDigest", pattern=_SHA256_PATTERN)
    next_state_digest: str = Field(alias="nextStateDigest", pattern=_SHA256_PATTERN)
    relationships: tuple[WalkingGraphRelationship, ...] = Field(min_length=3, max_length=3)

    @model_validator(mode="after")
    def validate_identity(self) -> WalkingObservationGraphSnapshot:
        relationship_ids = [item.relationship_id for item in self.relationships]
        if relationship_ids != sorted(set(relationship_ids)):
            raise ValueError("Walking Graph relationships must be unique and sorted")
        rule_bindings = {(item.rule_id, item.rule_digest) for item in self.relationships}
        if len(rule_bindings) != 1:
            raise ValueError("Walking Graph relationships must share one registered rule")
        shapes = {
            (
                item.source_kind,
                item.source_id,
                item.relation,
                item.target_kind,
                item.target_id,
            )
            for item in self.relationships
        }
        expected_shapes = {
            (
                "observation",
                self.observation_id,
                "supports",
                "hypothesis",
                self.hypothesis_id,
            ),
            (
                "observation",
                self.observation_id,
                "enables",
                "plan",
                self.plan_id,
            ),
            (
                "plan",
                self.plan_id,
                "depends-on",
                "hypothesis",
                self.hypothesis_id,
            ),
        }
        if shapes != expected_shapes:
            raise ValueError("Walking Graph relationship topology is malformed")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"snapshot_id", "snapshot_digest"},
        )
        digest = discovery_digest("pajin.walking.observation-graph/v1", material)
        snapshot_id = f"walking-observation-graph_{digest}"
        if self.snapshot_digest and self.snapshot_digest != digest:
            raise ValueError("Walking Observation Graph Digest differs")
        if self.snapshot_id and self.snapshot_id != snapshot_id:
            raise ValueError("Walking Observation Graph ID differs")
        self.snapshot_digest = digest
        self.snapshot_id = snapshot_id
        if fullmatch(_GRAPH_ID_PATTERN, self.snapshot_id) is None:
            raise ValueError("Walking Observation Graph ID is malformed")
        return self


class WalkingObservationReplanAuthority(StrictModel):
    """Complete content-addressed WALK-004 Observation-to-Replan authority."""

    api_version: Literal["pajin.dev/walking-observation-replan/v1alpha1"] = Field(
        default=WALKING_OBSERVATION_REPLAN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WalkingObservationReplanAuthority"] = "WalkingObservationReplanAuthority"
    authority_id: str = Field(default="", alias="authorityId")
    authority_digest: str = Field(default="", alias="authorityDigest")
    campaign_manifest: dict[str, JsonValue] = Field(alias="campaignManifest")
    campaign_digest: str = Field(alias="campaignDigest", pattern=_SHA256_PATTERN)
    source: SealedMCPAuthorizationHypothesisDependency
    rule: RegisteredWalkingObservationReplanRule
    evidence: MCPAuthorizationObservationEvidence
    observation: AdmittedMCPAuthorizationObservation
    plan: WalkingFollowUpPlan
    graph: WalkingObservationGraphSnapshot
    baseline_state_digest: str = Field(alias="baselineStateDigest", pattern=_SHA256_PATTERN)
    expected_previous_state_digest: str = Field(
        alias="expectedPreviousStateDigest",
        pattern=_SHA256_PATTERN,
    )
    state_path: tuple[str, ...] = Field(alias="statePath", min_length=2, max_length=4)

    @model_validator(mode="after")
    def validate_authority(self) -> WalkingObservationReplanAuthority:
        campaign = _validated_campaign_authority(self.campaign_manifest)
        hypothesis = self.source.hypothesis
        rag_snapshot = hypothesis.rag_dependency.hypothesis.surface_snapshot
        mcp_snapshot = hypothesis.mcp_surface_snapshot
        capability = hypothesis.capability.reference()
        if (
            self.campaign_digest != _campaign_digest(campaign)
            or campaign.metadata.name != hypothesis.campaign
            or self.campaign_digest != hypothesis.campaign_digest
            or (
                hypothesis.source_campaign_digest is not None
                and hypothesis.source_campaign_digest != campaign_manifest_digest(campaign)
            )
        ):
            raise ValueError("Walking Replan Campaign authority differs")
        if self.rule.source_hypothesis_rule_id != hypothesis.rule_id:
            raise ValueError("Walking Replan rule belongs to another Hypothesis rule")
        if (
            self.evidence.campaign != hypothesis.campaign
            or self.evidence.campaign_digest != hypothesis.campaign_digest
            or self.evidence.source_run_id != self.source.run_id
            or self.evidence.source_root_digest != self.source.root_digest
            or self.evidence.source_artifact_path != self.source.artifact_path
            or self.evidence.source_artifact_sha256 != self.source.artifact_sha256
            or self.evidence.hypothesis_id != hypothesis.hypothesis_id
            or self.evidence.hypothesis_digest != hypothesis.hypothesis_digest
            or self.evidence.observed_execution_state != hypothesis.execution_state
        ):
            raise ValueError("Walking Replan evidence differs from sealed source authority")
        if (
            self.observation.evidence != self.evidence
            or self.observation.rule_id != self.rule.rule_id
            or self.observation.rule_digest != self.rule.rule_digest
            or self.observation.observation_kind != self.rule.observation_kind
        ):
            raise ValueError("Walking Replan Observation differs from registered admission rule")
        plan = self.plan
        if (
            plan.campaign != hypothesis.campaign
            or plan.campaign_digest != hypothesis.campaign_digest
            or plan.previous_state_digest != self.expected_previous_state_digest
            or plan.observation_id != self.observation.observation_id
            or plan.observation_digest != self.observation.observation_digest
            or plan.hypothesis_id != hypothesis.hypothesis_id
            or plan.hypothesis_digest != hypothesis.hypothesis_digest
            or plan.rag_surface_snapshot_id != rag_snapshot.snapshot_id
            or plan.rag_surface_snapshot_digest != rag_snapshot.snapshot_digest
            or plan.mcp_surface_snapshot_id != mcp_snapshot.snapshot_id
            or plan.mcp_surface_snapshot_digest != mcp_snapshot.snapshot_digest
            or plan.required_capability != capability
            or plan.authorization_control != hypothesis.authorization_control
            or plan.action != self.rule.next_action
        ):
            raise ValueError("Walking Replan Plan expands or differs from admitted authority")
        if self.baseline_state_digest != _baseline_state_digest(campaign, self.source):
            raise ValueError("Walking Replan baseline state differs from sealed authority")
        if self.state_path[0] != self.baseline_state_digest:
            raise ValueError("Walking Replan state path starts outside its baseline authority")
        if len(self.state_path) != len(set(self.state_path)):
            raise ValueError("Walking Replan state path contains a cycle or repeated state")
        if self.state_path[-2] != self.expected_previous_state_digest:
            raise ValueError("Walking Replan expected previous state is stale")
        if self.state_path[-1] != plan.plan_state_digest:
            raise ValueError("Walking Replan state path does not end at the selected Plan")
        if self.expected_previous_state_digest == plan.plan_state_digest:
            raise ValueError("Walking Replan selected a repeated state")
        self._validate_graph()
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = discovery_digest("pajin.walking.observation-replan-authority/v1", material)
        authority_id = f"walking-observation-replan_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Walking Observation Replan authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Walking Observation Replan authority ID differs")
        self.authority_digest = digest
        self.authority_id = authority_id
        if fullmatch(_AUTHORITY_ID_PATTERN, self.authority_id) is None:
            raise ValueError("Walking Observation Replan authority ID is malformed")
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Walking Observation Replan authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self

    def _validate_graph(self) -> None:
        graph = self.graph
        expected_relationships = _relationships(self.rule, self.observation, self.plan)
        if (
            graph.campaign != self.source.hypothesis.campaign
            or graph.campaign_digest != self.campaign_digest
            or graph.source_run_id != self.source.run_id
            or graph.source_root_digest != self.source.root_digest
            or graph.hypothesis_id != self.source.hypothesis.hypothesis_id
            or graph.hypothesis_digest != self.source.hypothesis.hypothesis_digest
            or graph.observation_id != self.observation.observation_id
            or graph.observation_digest != self.observation.observation_digest
            or graph.plan_id != self.plan.plan_id
            or graph.plan_digest != self.plan.plan_digest
            or graph.previous_state_digest != self.expected_previous_state_digest
            or graph.next_state_digest != self.plan.plan_state_digest
            or graph.relationships != expected_relationships
        ):
            raise ValueError("Walking Observation Graph differs from exact Replan authority")


@dataclass(frozen=True, slots=True)
class _VerifiedMCPDependency:
    root_digest: str
    artifact_sha256: str
    hypothesis: MCPToolAuthorizationHypothesisAuthority


def _load_mcp_dependency(
    campaign: CampaignManifest,
    outcome: MCPToolAuthorizationHypothesisOutcome,
) -> _VerifiedMCPDependency:
    try:
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_AUTHORITY_BYTES,
                outcome.artifact_path: _MAX_AUTHORITY_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        artifact = snapshot.artifact_bytes(outcome.artifact_path)
        raw = json.loads(artifact)
        if type(raw) is not list:
            raise ValueError("WALK-003 Hypothesis artifact must be a list")
        hypotheses = tuple(
            MCPToolAuthorizationHypothesisAuthority.model_validate(item)
            for item in cast(list[object], raw)
        )
    except (OSError, RunIntegrityError, ValueError) as exc:
        raise WalkingObservationReplanError(
            "WALK-003 MCP Hypothesis dependency is not sealed and valid"
        ) from exc
    if sealed_campaign != campaign or hypotheses != outcome.hypotheses:
        raise WalkingObservationReplanError(
            "WALK-003 MCP Hypothesis dependency differs from sealed authority"
        )
    if len(hypotheses) != 1:
        raise WalkingObservationReplanError(
            "WALK-004 requires exactly one canonical MCP authorization Hypothesis"
        )
    hypothesis = hypotheses[0]
    created = [
        event
        for event in snapshot.events
        if event.event_type == "walking.mcp-tool-authorization-hypotheses.created"
    ]
    expected_payload = {
        "artifact": outcome.artifact_path,
        "compilerId": hypothesis.compiler_id,
        "hypothesisIds": [hypothesis.hypothesis_id],
        "hypothesisDigests": [hypothesis.hypothesis_digest],
        "mcpSurfaceSnapshotId": hypothesis.mcp_surface_snapshot.snapshot_id,
        "mcpSurfaceSnapshotDigest": hypothesis.mcp_surface_snapshot.snapshot_digest,
        "executionState": "registered-not-authorized",
    }
    if len(created) != 1 or created[0].payload != expected_payload:
        raise WalkingObservationReplanError(
            "WALK-003 MCP Hypothesis publication event differs from authority"
        )
    return _VerifiedMCPDependency(
        root_digest=snapshot.verification.root_digest,
        artifact_sha256=sha256(artifact).hexdigest(),
        hypothesis=hypothesis,
    )


def _dependency(
    outcome: MCPToolAuthorizationHypothesisOutcome,
    verified: _VerifiedMCPDependency,
) -> SealedMCPAuthorizationHypothesisDependency:
    return SealedMCPAuthorizationHypothesisDependency(
        runId=outcome.run_id,
        rootDigest=verified.root_digest,
        artifactPath=outcome.artifact_path,
        artifactSha256=verified.artifact_sha256,
        hypothesis=verified.hypothesis.model_copy(deep=True),
    )


def load_sealed_mcp_authorization_hypothesis_dependency(
    campaign: CampaignManifest,
    outcome: MCPToolAuthorizationHypothesisOutcome,
) -> SealedMCPAuthorizationHypothesisDependency:
    """Reopen one exact sealed WALK-003 authority for additive consumers."""

    authoritative_campaign = CampaignManifest.model_validate(
        campaign.model_dump(mode="json", by_alias=True)
    )
    return _dependency(
        outcome,
        _load_mcp_dependency(authoritative_campaign, outcome),
    )


def _baseline_state_digest(
    campaign: CampaignManifest,
    source: SealedMCPAuthorizationHypothesisDependency,
) -> str:
    hypothesis = source.hypothesis
    rag_snapshot = hypothesis.rag_dependency.hypothesis.surface_snapshot
    mcp_snapshot = hypothesis.mcp_surface_snapshot
    return discovery_digest(
        "pajin.walking.observation-replan-baseline-state/v1",
        {
            "campaignDigest": _campaign_digest(campaign),
            "sourceRunId": source.run_id,
            "sourceRootDigest": source.root_digest,
            "sourceArtifactPath": source.artifact_path,
            "sourceArtifactSha256": source.artifact_sha256,
            "hypothesisId": hypothesis.hypothesis_id,
            "hypothesisDigest": hypothesis.hypothesis_digest,
            "ragSurfaceSnapshotId": rag_snapshot.snapshot_id,
            "ragSurfaceSnapshotDigest": rag_snapshot.snapshot_digest,
            "mcpSurfaceSnapshotId": mcp_snapshot.snapshot_id,
            "mcpSurfaceSnapshotDigest": mcp_snapshot.snapshot_digest,
            "capability": hypothesis.capability.reference().model_dump(mode="json", by_alias=True),
            "authorizationControl": hypothesis.authorization_control,
            "executionState": hypothesis.execution_state,
        },
    )


def _campaign_authority_payload(campaign: CampaignManifest) -> dict[str, JsonValue]:
    payload = cast(
        dict[str, JsonValue],
        campaign.model_dump(mode="json", by_alias=True),
    )
    spec = cast(dict[str, JsonValue], payload["spec"])
    rules = cast(dict[str, JsonValue], spec["rulesOfEngagement"])
    for field_name in ("allowedMethods", "allowedToolCategories", "prohibit", "stopOn"):
        rules[field_name] = cast(JsonValue, sorted(cast(list[str], rules[field_name])))
    for window in cast(list[dict[str, JsonValue]], rules["testingWindows"]):
        window["days"] = cast(JsonValue, sorted(cast(list[str], window["days"])))
    return payload


def _validated_campaign_authority(payload: dict[str, JsonValue]) -> CampaignManifest:
    campaign = CampaignManifest.model_validate(payload)
    if payload != _campaign_authority_payload(campaign):
        raise ValueError("Walking Replan Campaign manifest is not canonical")
    return campaign


def _relationships(
    rule: RegisteredWalkingObservationReplanRule,
    observation: AdmittedMCPAuthorizationObservation,
    plan: WalkingFollowUpPlan,
) -> tuple[WalkingGraphRelationship, ...]:
    values = (
        WalkingGraphRelationship(
            sourceKind="observation",
            sourceId=observation.observation_id,
            relation=rule.support_relation,
            targetKind="hypothesis",
            targetId=observation.hypothesis_id,
            ruleId=rule.rule_id,
            ruleDigest=rule.rule_digest,
        ),
        WalkingGraphRelationship(
            sourceKind="observation",
            sourceId=observation.observation_id,
            relation=rule.enable_relation,
            targetKind="plan",
            targetId=plan.plan_id,
            ruleId=rule.rule_id,
            ruleDigest=rule.rule_digest,
        ),
        WalkingGraphRelationship(
            sourceKind="plan",
            sourceId=plan.plan_id,
            relation=rule.dependency_relation,
            targetKind="hypothesis",
            targetId=observation.hypothesis_id,
            ruleId=rule.rule_id,
            ruleDigest=rule.rule_digest,
        ),
    )
    return tuple(sorted(values, key=lambda item: item.relationship_id))


class DeterministicWalkingObservationReplanCompiler:
    """Admit exact WALK-003 state and select one bounded non-executable Plan."""

    def __init__(self, *, rule: RegisteredWalkingObservationReplanRule) -> None:
        self._rule = RegisteredWalkingObservationReplanRule.model_validate(
            rule.model_dump(mode="json", by_alias=True)
        )

    def evidence(
        self,
        campaign: CampaignManifest,
        source_outcome: MCPToolAuthorizationHypothesisOutcome,
    ) -> MCPAuthorizationObservationEvidence:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        verified = _load_mcp_dependency(authoritative_campaign, source_outcome)
        source = _dependency(source_outcome, verified)
        hypothesis = source.hypothesis
        return MCPAuthorizationObservationEvidence(
            campaign=hypothesis.campaign,
            campaignDigest=hypothesis.campaign_digest,
            sourceRunId=source.run_id,
            sourceRootDigest=source.root_digest,
            sourceArtifactPath=source.artifact_path,
            sourceArtifactSha256=source.artifact_sha256,
            hypothesisId=hypothesis.hypothesis_id,
            hypothesisDigest=hypothesis.hypothesis_digest,
            observedExecutionState=hypothesis.execution_state,
        )

    def baseline_state_digest(
        self,
        campaign: CampaignManifest,
        source_outcome: MCPToolAuthorizationHypothesisOutcome,
    ) -> str:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        verified = _load_mcp_dependency(authoritative_campaign, source_outcome)
        return _baseline_state_digest(
            authoritative_campaign,
            _dependency(source_outcome, verified),
        )

    def compile(
        self,
        campaign: CampaignManifest,
        source_outcome: MCPToolAuthorizationHypothesisOutcome,
        evidence: MCPAuthorizationObservationEvidence,
        *,
        expected_previous_state_digest: str,
        prior_outcome: WalkingObservationReplanOutcome | None = None,
    ) -> WalkingObservationReplanAuthority:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        verified = _load_mcp_dependency(authoritative_campaign, source_outcome)
        source = _dependency(source_outcome, verified)
        hypothesis = source.hypothesis
        try:
            candidate = MCPAuthorizationObservationEvidence.model_validate(
                evidence.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValueError) as exc:
            raise WalkingObservationReplanError(
                "Walking Observation evidence is malformed or forged"
            ) from exc
        expected_evidence = MCPAuthorizationObservationEvidence(
            campaign=hypothesis.campaign,
            campaignDigest=hypothesis.campaign_digest,
            sourceRunId=source.run_id,
            sourceRootDigest=source.root_digest,
            sourceArtifactPath=source.artifact_path,
            sourceArtifactSha256=source.artifact_sha256,
            hypothesisId=hypothesis.hypothesis_id,
            hypothesisDigest=hypothesis.hypothesis_digest,
            observedExecutionState=hypothesis.execution_state,
        )
        if candidate != expected_evidence:
            raise WalkingObservationReplanError(
                "Walking Observation evidence differs from sealed WALK-003 authority"
            )
        rule = self._rule
        if (
            rule.source_hypothesis_rule_id != hypothesis.rule_id
            or rule.observed_execution_state != hypothesis.execution_state
        ):
            raise WalkingObservationReplanError(
                "Walking Observation rule differs from WALK-003 authority"
            )
        baseline = _baseline_state_digest(authoritative_campaign, source)
        history = self._verified_history(
            authoritative_campaign,
            source,
            candidate,
            baseline,
            prior_outcome,
        )
        if expected_previous_state_digest != history[-1]:
            raise WalkingObservationReplanError("Walking Replan expected state is stale")
        observation = AdmittedMCPAuthorizationObservation(
            campaign=hypothesis.campaign,
            campaignDigest=hypothesis.campaign_digest,
            evidence=candidate,
            ruleId=rule.rule_id,
            ruleDigest=rule.rule_digest,
            hypothesisId=hypothesis.hypothesis_id,
            hypothesisDigest=hypothesis.hypothesis_digest,
            observationKind=rule.observation_kind,
            observedExecutionState=hypothesis.execution_state,
        )
        rag_snapshot = hypothesis.rag_dependency.hypothesis.surface_snapshot
        mcp_snapshot = hypothesis.mcp_surface_snapshot
        plan = WalkingFollowUpPlan(
            campaign=hypothesis.campaign,
            campaignDigest=hypothesis.campaign_digest,
            previousStateDigest=history[-1],
            observationId=observation.observation_id,
            observationDigest=observation.observation_digest,
            hypothesisId=hypothesis.hypothesis_id,
            hypothesisDigest=hypothesis.hypothesis_digest,
            ragSurfaceSnapshotId=rag_snapshot.snapshot_id,
            ragSurfaceSnapshotDigest=rag_snapshot.snapshot_digest,
            mcpSurfaceSnapshotId=mcp_snapshot.snapshot_id,
            mcpSurfaceSnapshotDigest=mcp_snapshot.snapshot_digest,
            requiredCapability=hypothesis.capability.reference(),
            authorizationControl=hypothesis.authorization_control,
            action=rule.next_action,
        )
        if plan.plan_state_digest in history:
            raise WalkingObservationReplanError("Walking Replan selected a cycle or repeated state")
        relationships = _relationships(rule, observation, plan)
        graph = WalkingObservationGraphSnapshot(
            campaign=hypothesis.campaign,
            campaignDigest=hypothesis.campaign_digest,
            sourceRunId=source.run_id,
            sourceRootDigest=source.root_digest,
            hypothesisId=hypothesis.hypothesis_id,
            hypothesisDigest=hypothesis.hypothesis_digest,
            observationId=observation.observation_id,
            observationDigest=observation.observation_digest,
            planId=plan.plan_id,
            planDigest=plan.plan_digest,
            previousStateDigest=history[-1],
            nextStateDigest=plan.plan_state_digest,
            relationships=relationships,
        )
        return WalkingObservationReplanAuthority(
            campaignManifest=_campaign_authority_payload(authoritative_campaign),
            campaignDigest=hypothesis.campaign_digest,
            source=source,
            rule=rule.model_copy(deep=True),
            evidence=candidate,
            observation=observation,
            plan=plan,
            graph=graph,
            baselineStateDigest=baseline,
            expectedPreviousStateDigest=history[-1],
            statePath=(*history, plan.plan_state_digest),
        )

    def _verified_history(
        self,
        campaign: CampaignManifest,
        source: SealedMCPAuthorizationHypothesisDependency,
        evidence: MCPAuthorizationObservationEvidence,
        baseline: str,
        prior_outcome: WalkingObservationReplanOutcome | None,
    ) -> tuple[str, ...]:
        if prior_outcome is None:
            return (baseline,)
        prior = load_walking_observation_replan_authority(campaign, prior_outcome)
        if (
            prior.source != source
            or prior.rule != self._rule
            or prior.evidence != evidence
            or prior.baseline_state_digest != baseline
        ):
            raise WalkingObservationReplanError(
                "Walking Replan prior authority belongs to another source state"
            )
        return prior.state_path


@dataclass(frozen=True, slots=True)
class WalkingObservationReplanOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    authority: WalkingObservationReplanAuthority


class WalkingObservationReplanRunner:
    """Seal WALK-004 admission, Graph, and Plan without creating execution authority."""

    def __init__(
        self,
        *,
        compiler: DeterministicWalkingObservationReplanCompiler,
        output_root: Path,
    ) -> None:
        if not isinstance(compiler, DeterministicWalkingObservationReplanCompiler):
            raise TypeError("Walking Observation Replan Runner requires its deterministic Compiler")
        self._compiler = compiler
        self._output_root = output_root

    def run(
        self,
        campaign: CampaignManifest,
        source_outcome: MCPToolAuthorizationHypothesisOutcome,
        evidence: MCPAuthorizationObservationEvidence,
        *,
        expected_previous_state_digest: str,
    ) -> WalkingObservationReplanOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        authority = self._compiler.compile(
            authoritative_campaign,
            source_outcome,
            evidence,
            expected_previous_state_digest=expected_previous_state_digest,
        )
        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "walking-observation-replan",
            },
        )
        store.write_json(
            "campaign.json",
            authoritative_campaign.model_dump(mode="json", by_alias=True),
        )
        artifact_path = store.write_json(
            "walking-observation-replan-authority.json",
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "walking.observation-replan-authority.created",
            {
                "artifact": artifact_path,
                "authorityId": authority.authority_id,
                "authorityDigest": authority.authority_digest,
                "observationId": authority.observation.observation_id,
                "observationDigest": authority.observation.observation_digest,
                "graphSnapshotId": authority.graph.snapshot_id,
                "graphSnapshotDigest": authority.graph.snapshot_digest,
                "planId": authority.plan.plan_id,
                "planDigest": authority.plan.plan_digest,
                "action": authority.plan.action,
                "executionState": authority.plan.execution_state,
            },
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "walking-observation-replan-authority-sealed",
                "purpose": "walking-observation-replan",
                "authorityId": authority.authority_id,
                "executionState": authority.plan.execution_state,
            },
        )
        store.append_event(
            "campaign.completed",
            {
                "purpose": "walking-observation-replan",
                "artifact": artifact_path,
            },
        )
        store.seal()
        return WalkingObservationReplanOutcome(
            run_id=store.run_id,
            run_path=store.path,
            artifact_path=artifact_path,
            authority=authority.model_copy(deep=True),
        )


def load_walking_observation_replan_authority(
    campaign: CampaignManifest,
    outcome: WalkingObservationReplanOutcome,
) -> WalkingObservationReplanAuthority:
    """Reconstruct and verify complete WALK-004 authority from its sealed artifact and audit."""

    try:
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_AUTHORITY_BYTES,
                outcome.artifact_path: _MAX_AUTHORITY_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        authority = WalkingObservationReplanAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.artifact_path)
        )
    except (OSError, RunIntegrityError, ValueError) as exc:
        raise WalkingObservationReplanError(
            "WALK-004 Observation Replan authority is not sealed and valid"
        ) from exc
    if sealed_campaign != campaign or authority != outcome.authority:
        raise WalkingObservationReplanError(
            "WALK-004 Observation Replan outcome differs from sealed authority"
        )
    created = [
        event
        for event in snapshot.events
        if event.event_type == "walking.observation-replan-authority.created"
    ]
    expected_payload = {
        "artifact": outcome.artifact_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "observationId": authority.observation.observation_id,
        "observationDigest": authority.observation.observation_digest,
        "graphSnapshotId": authority.graph.snapshot_id,
        "graphSnapshotDigest": authority.graph.snapshot_digest,
        "planId": authority.plan.plan_id,
        "planDigest": authority.plan.plan_digest,
        "action": authority.plan.action,
        "executionState": authority.plan.execution_state,
    }
    if len(created) != 1 or created[0].payload != expected_payload:
        raise WalkingObservationReplanError(
            "WALK-004 Observation Replan publication event differs from authority"
        )
    return authority.model_copy(deep=True)
