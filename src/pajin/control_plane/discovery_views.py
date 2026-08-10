"""Verified, read-only Discovery Surface and wave projections for operators."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from pathlib import Path
from re import fullmatch
from typing import Literal

from pydantic import Field, TypeAdapter

from pajin.discovery.hypothesis import (
    AttackHypothesisSet,
    HypothesisWavePlan,
    SurfaceBoundPlan,
)
from pajin.discovery.models import AttackSurfaceSet, SurfaceLocator
from pajin.discovery.recon import ReconWavePlan
from pajin.domain.models import CampaignManifest, StrictModel, ToolResult, campaign_manifest_digest
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    AuditEvent,
    RunIntegrityError,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
)

_CAMPAIGN_PATTERN = r"^[a-z0-9][a-z0-9-]{2,79}$"
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024


class DiscoveryViewUnavailable(RuntimeError):
    """Raised when no server-owned Discovery Run root is configured."""


class DiscoveryViewNotFound(RuntimeError):
    """Raised when an exact Campaign/Run tuple does not exist."""


class DiscoveryViewIntegrityError(RuntimeError):
    """Raised when sealed Discovery authorities do not agree."""


class DiscoveryCampaignView(StrictModel):
    name: str = Field(pattern=_CAMPAIGN_PATTERN)
    digest: str = Field(pattern=_SHA256_PATTERN)


class DiscoveryRunAuthorityView(StrictModel):
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    root_digest: str = Field(alias="rootDigest", pattern=_SHA256_PATTERN)
    state: Literal["completed"] = "completed"


class DiscoverySurfaceSnapshotView(StrictModel):
    snapshot_id: str = Field(alias="snapshotId")
    snapshot_digest: str = Field(alias="snapshotDigest", pattern=_SHA256_PATTERN)
    revision: Literal[1] = 1
    surface_set_id: str = Field(alias="surfaceSetId")
    source_run_id: str = Field(alias="sourceRunId", pattern=_RUN_ID_PATTERN)
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=_SHA256_PATTERN)
    projection_run_id: str = Field(alias="projectionRunId", pattern=_RUN_ID_PATTERN)
    projection_root_digest: str = Field(
        alias="projectionRootDigest",
        pattern=_SHA256_PATTERN,
    )
    artifact_sha256: str = Field(alias="artifactSha256", pattern=_SHA256_PATTERN)


class DiscoverySurfaceView(StrictModel):
    surface_id: str = Field(alias="surfaceId")
    target_id: str = Field(alias="targetId")
    locator: SurfaceLocator
    confidence: float = Field(ge=0, le=1)
    observation_count: int = Field(alias="observationCount", ge=1)
    first_observed_at: datetime = Field(alias="firstObservedAt")
    last_observed_at: datetime = Field(alias="lastObservedAt")


class DiscoverySurfaceSetView(StrictModel):
    surface_set_id: str = Field(alias="surfaceSetId")
    generated_at: datetime = Field(alias="generatedAt")
    surface_count: int = Field(alias="surfaceCount", ge=0, le=500)
    observation_count: int = Field(alias="observationCount", ge=0)
    surfaces: list[DiscoverySurfaceView] = Field(max_length=500)


class DiscoveryWaveTaskView(StrictModel):
    hypothesis_id: str = Field(alias="hypothesisId")
    surface_id: str = Field(alias="surfaceId")
    specialist_id: str = Field(alias="specialistId")
    threat_class: str = Field(alias="threatClass")


class ReconWaveView(StrictModel):
    kind: Literal["recon"] = "recon"
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    state: Literal["completed"] = "completed"
    stop_condition: Literal["single-wave-complete"] = Field(alias="stopCondition")
    task_count: Literal[1] = Field(alias="taskCount")


class HypothesisWaveView(StrictModel):
    kind: Literal["hypothesis"] = "hypothesis"
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    state: Literal["completed"] = "completed"
    wave_plan_id: str = Field(alias="wavePlanId")
    stop_condition: Literal["hypothesis-wave-complete"] = Field(alias="stopCondition")
    task_count: int = Field(alias="taskCount", ge=1, le=100)
    tasks: list[DiscoveryWaveTaskView] = Field(min_length=1, max_length=100)


class DiscoveryViewAuthorityBoundary(StrictModel):
    surface_snapshot_verified: Literal[True] = Field(
        default=True,
        alias="surfaceSnapshotVerified",
    )
    canonical_graph_included: Literal[False] = Field(
        default=False,
        alias="canonicalGraphIncluded",
    )
    view_grants_capability: Literal[False] = Field(
        default=False,
        alias="viewGrantsCapability",
    )
    view_grants_permit: Literal[False] = Field(default=False, alias="viewGrantsPermit")
    view_authorizes_execution: Literal[False] = Field(
        default=False,
        alias="viewAuthorizesExecution",
    )


class VerifiedDiscoverySurfaceWaveView(StrictModel):
    api_version: Literal["pajin.control-plane/verified-discovery-surface-wave-view/v1alpha1"] = (
        Field(
            default="pajin.control-plane/verified-discovery-surface-wave-view/v1alpha1",
            alias="apiVersion",
        )
    )
    kind: Literal["VerifiedDiscoverySurfaceWaveView"] = "VerifiedDiscoverySurfaceWaveView"
    campaign: DiscoveryCampaignView
    hypothesis_run: DiscoveryRunAuthorityView = Field(alias="hypothesisRun")
    surface_snapshot: DiscoverySurfaceSnapshotView = Field(alias="surfaceSnapshot")
    surface_set: DiscoverySurfaceSetView = Field(alias="surfaceSet")
    waves: tuple[ReconWaveView, HypothesisWaveView]
    authority_boundary: DiscoveryViewAuthorityBoundary = Field(alias="authorityBoundary")


class _HypothesisRunState(StrictModel):
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    status: Literal["completed"]
    stage: Literal["hypothesis-wave-finalization"]
    purpose: Literal["dynamic-hypothesis-wave"]
    hypothesis_set_id: str = Field(alias="hypothesisSetId")
    wave_plan_id: str = Field(alias="wavePlanId")
    stop_condition: Literal["hypothesis-wave-complete"] = Field(alias="stopCondition")
    surface_snapshot_id: str = Field(alias="surfaceSnapshotId")
    surface_snapshot_revision: Literal[1] = Field(alias="surfaceSnapshotRevision")
    surface_snapshot_digest: str = Field(alias="surfaceSnapshotDigest", pattern=_SHA256_PATTERN)
    surface_bound_plan_digest: str = Field(
        alias="surfaceBoundPlanDigest",
        pattern=_SHA256_PATTERN,
    )


class _ReconRunState(StrictModel):
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    status: Literal["completed"]
    stage: Literal["recon-source-finalization"]
    purpose: Literal["single-recon-wave"]
    evidence: str
    stop_condition: Literal["single-wave-complete"] = Field(alias="stopCondition")


class VerifiedDiscoveryViewReader:
    """Project three sealed Discovery Runs without creating new authority."""

    def __init__(self, root: Path | None) -> None:
        self._root = self._validated_root(root) if root is not None else None

    def read(self, *, campaign: str, hypothesis_run_id: str) -> VerifiedDiscoverySurfaceWaveView:
        if self._root is None:
            raise DiscoveryViewUnavailable("Discovery Run views are not configured")
        _require_identifier(campaign, _CAMPAIGN_PATTERN, label="Campaign")
        _require_identifier(hypothesis_run_id, _RUN_ID_PATTERN, label="Hypothesis Run")
        try:
            hypothesis_path = self._run_path(campaign, hypothesis_run_id)
            hypothesis_snapshot = load_verified_run_artifacts(
                hypothesis_path,
                requests={
                    "campaign.json": _MAX_ARTIFACT_BYTES,
                    "hypothesis-set.json": _MAX_ARTIFACT_BYTES,
                    "hypothesis-wave-plan.json": _MAX_ARTIFACT_BYTES,
                    "surface-bound-plan.json": _MAX_ARTIFACT_BYTES,
                    "hypothesis-results.json": _MAX_ARTIFACT_BYTES,
                    "run.json": _MAX_ARTIFACT_BYTES,
                },
                expected_run_id=hypothesis_run_id,
            )
            authorities = self._parse_hypothesis_authority(hypothesis_snapshot)
            manifest, hypothesis_set, plan, bound_plan, results, run_state = authorities
            self._verify_hypothesis_authority(
                hypothesis_snapshot,
                manifest=manifest,
                hypothesis_set=hypothesis_set,
                plan=plan,
                bound_plan=bound_plan,
                results=results,
                run_state=run_state,
                requested_campaign=campaign,
            )
            surface_set, recon_plan = self._load_surface_authority(
                manifest=manifest,
                bound_plan=bound_plan,
            )
        except DiscoveryViewNotFound:
            raise
        except (KeyError, OSError, RunIntegrityError, TypeError, ValueError) as exc:
            raise DiscoveryViewIntegrityError(
                "Discovery Surface/Wave authority is not integrity-valid"
            ) from exc
        return _build_view(
            hypothesis_snapshot=hypothesis_snapshot,
            manifest=manifest,
            hypothesis_set=hypothesis_set,
            plan=plan,
            bound_plan=bound_plan,
            surface_set=surface_set,
            recon_plan=recon_plan,
        )

    @staticmethod
    def _validated_root(root: Path) -> Path:
        try:
            if _is_link(root):
                raise ValueError("Discovery Run root cannot be a link")
            resolved = root.resolve(strict=True)
        except OSError as exc:
            raise ValueError("Discovery Run root is unavailable") from exc
        if not resolved.is_dir() or _is_link(resolved):
            raise ValueError("Discovery Run root must be a real directory")
        return resolved

    def _run_path(self, campaign: str, run_id: str) -> Path:
        assert self._root is not None
        _require_identifier(campaign, _CAMPAIGN_PATTERN, label="Campaign")
        _require_identifier(run_id, _RUN_ID_PATTERN, label="Run")
        campaign_path = self._root / campaign
        candidate = campaign_path / run_id
        try:
            if _is_link(campaign_path) or _is_link(candidate):
                raise DiscoveryViewIntegrityError("Discovery Run path cannot be a link")
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise DiscoveryViewNotFound("Discovery Campaign/Run was not found") from exc
        if not candidate.is_dir() or resolved != candidate:
            raise DiscoveryViewIntegrityError("Discovery Run escaped its configured root")
        return resolved

    @staticmethod
    def _parse_hypothesis_authority(
        snapshot: VerifiedRunSnapshot,
    ) -> tuple[
        CampaignManifest,
        AttackHypothesisSet,
        HypothesisWavePlan,
        SurfaceBoundPlan,
        tuple[ToolResult, ...],
        _HypothesisRunState,
    ]:
        manifest = CampaignManifest.model_validate(
            _strict_json(snapshot, "campaign.json", "Hypothesis Campaign")
        )
        hypothesis_set = AttackHypothesisSet.model_validate(
            _strict_json(snapshot, "hypothesis-set.json", "Hypothesis Set")
        )
        plan = HypothesisWavePlan.model_validate(
            _strict_json(snapshot, "hypothesis-wave-plan.json", "Hypothesis Wave Plan")
        )
        bound_plan = SurfaceBoundPlan.model_validate(
            _strict_json(snapshot, "surface-bound-plan.json", "Surface-bound Plan")
        )
        results = tuple(
            TypeAdapter(list[ToolResult]).validate_python(
                _strict_json(snapshot, "hypothesis-results.json", "Hypothesis results")
            )
        )
        run_state = _HypothesisRunState.model_validate(
            _strict_json(snapshot, "run.json", "Hypothesis Run state")
        )
        return manifest, hypothesis_set, plan, bound_plan, results, run_state

    @staticmethod
    def _verify_hypothesis_authority(
        snapshot: VerifiedRunSnapshot,
        *,
        manifest: CampaignManifest,
        hypothesis_set: AttackHypothesisSet,
        plan: HypothesisWavePlan,
        bound_plan: SurfaceBoundPlan,
        results: tuple[ToolResult, ...],
        run_state: _HypothesisRunState,
        requested_campaign: str,
    ) -> None:
        authority = bound_plan.surface_snapshot
        hypothesis_ids = [item.hypothesis_id for item in hypothesis_set.hypotheses]
        steps = plan.steps
        task_digests = [item.task_digest for item in bound_plan.tasks]
        if (
            manifest.metadata.name != requested_campaign
            or hypothesis_set.campaign != requested_campaign
            or authority.campaign != requested_campaign
            or authority.campaign_digest != campaign_manifest_digest(manifest)
            or snapshot.verification.run_id != run_state.run_id
            or hypothesis_set.compiler_id != plan.compiler_id
            or hypothesis_set.hypothesis_set_id != plan.hypothesis_set_id
            or hypothesis_set.hypothesis_set_id != bound_plan.hypothesis_set_id
            or plan.wave_plan_id != bound_plan.wave_plan_id
            or hypothesis_set.surface_set_id != authority.surface_set_id
            or hypothesis_set.source_projection_run_id != authority.projection_run_id
            or hypothesis_set.source_projection_root_digest != authority.projection_root_digest
            or hypothesis_set.source_surface_artifact_sha256 != authority.artifact_sha256
            or hypothesis_ids != [item.hypothesis_id for item in steps]
            or steps != [item.step for item in bound_plan.tasks]
            or len(results) != len(steps)
            or any(
                result.request_id != step.request.request_id
                or result.tool_id != step.request.tool_id
                or not result.success
                or result.error is not None
                or result.started_at.tzinfo is None
                or result.started_at.utcoffset() is None
                or result.finished_at.tzinfo is None
                or result.finished_at.utcoffset() is None
                or result.finished_at < result.started_at
                for step, result in zip(steps, results, strict=True)
            )
            or run_state.hypothesis_set_id != hypothesis_set.hypothesis_set_id
            or run_state.wave_plan_id != plan.wave_plan_id
            or run_state.surface_snapshot_id != authority.snapshot_id
            or run_state.surface_snapshot_revision != authority.revision
            or run_state.surface_snapshot_digest != authority.snapshot_digest
            or run_state.surface_bound_plan_digest != bound_plan.plan_digest
        ):
            raise DiscoveryViewIntegrityError("Hypothesis Run artifacts disagree")

        compiled = _single_event(snapshot, "discovery.hypothesis-set.compiled")
        completed = _single_event(snapshot, "discovery.hypothesis-wave.completed")
        terminal = _single_event(snapshot, "campaign.completed")
        expected_common = {
            "surfaceSnapshotId": authority.snapshot_id,
            "surfaceSnapshotRevision": authority.revision,
            "surfaceSnapshotDigest": authority.snapshot_digest,
            "surfaceBoundPlanDigest": bound_plan.plan_digest,
            "surfaceBoundTaskDigests": task_digests,
        }
        if (
            any(compiled.payload.get(key) != value for key, value in expected_common.items())
            or any(completed.payload.get(key) != value for key, value in expected_common.items())
            or compiled.payload.get("compilerId") != hypothesis_set.compiler_id
            or compiled.payload.get("hypothesisSetId") != hypothesis_set.hypothesis_set_id
            or compiled.payload.get("surfaceSetId") != hypothesis_set.surface_set_id
            or compiled.payload.get("sourceProjectionRunId") != authority.projection_run_id
            or compiled.payload.get("sourceProjectionRootDigest")
            != authority.projection_root_digest
            or compiled.payload.get("hypothesisIds") != hypothesis_ids
            or compiled.payload.get("hypothesisCount") != len(hypothesis_ids)
            or completed.payload.get("wavePlanId") != plan.wave_plan_id
            or completed.payload.get("hypothesisSetId") != hypothesis_set.hypothesis_set_id
            or completed.payload.get("hypothesisIds") != hypothesis_ids
            or completed.payload.get("requestIds") != [item.request_id for item in results]
            or completed.payload.get("toolCalls") != len(results)
            or completed.payload.get("maxWaves") != plan.max_waves
            or completed.payload.get("stopCondition") != plan.stop_condition
            or terminal.payload
            != {
                "purpose": "dynamic-hypothesis-wave",
                "hypothesisSetId": hypothesis_set.hypothesis_set_id,
            }
        ):
            raise DiscoveryViewIntegrityError("Hypothesis Run event authority disagrees")

    def _load_surface_authority(
        self,
        *,
        manifest: CampaignManifest,
        bound_plan: SurfaceBoundPlan,
    ) -> tuple[AttackSurfaceSet, ReconWavePlan]:
        authority = bound_plan.surface_snapshot
        source = load_verified_run_artifacts(
            self._run_path(authority.campaign, authority.source_run_id),
            requests={
                "campaign.json": _MAX_ARTIFACT_BYTES,
                "recon-plan.json": _MAX_ARTIFACT_BYTES,
                "run.json": _MAX_ARTIFACT_BYTES,
            },
            expected_run_id=authority.source_run_id,
        )
        sealed_campaign = CampaignManifest.model_validate(
            _strict_json(source, "campaign.json", "Recon Campaign")
        )
        recon_plan = ReconWavePlan.model_validate(
            _strict_json(source, "recon-plan.json", "Recon Wave Plan")
        )
        recon_state = _ReconRunState.model_validate(
            _strict_json(source, "run.json", "Recon Run state")
        )
        if (
            sealed_campaign != manifest
            or source.verification.root_digest != authority.source_root_digest
            or recon_state.run_id != authority.source_run_id
            or recon_state.stop_condition != recon_plan.stop_condition
        ):
            raise DiscoveryViewIntegrityError("Recon source authority disagrees")
        targets = [item for item in manifest.spec.targets if item.id == recon_plan.target_id]
        if len(targets) != 1 or recon_plan.request.target != targets[0].endpoint:
            raise DiscoveryViewIntegrityError("Recon Plan target differs from Campaign")
        completed = _single_event(source, "discovery.recon-wave.completed")
        terminal = _single_event(source, "campaign.completed")
        if (
            completed.payload.get("plannerId") != recon_plan.planner_id
            or completed.payload.get("requestId") != recon_plan.request.request_id
            or completed.payload.get("toolId") != recon_plan.request.tool_id
            or completed.payload.get("evidence") != recon_state.evidence
            or completed.payload.get("requiredSurfaceKinds")
            != list(recon_plan.required_surface_kinds)
            or completed.payload.get("toolCalls") != 1
            or completed.payload.get("stopCondition") != recon_plan.stop_condition
            or terminal.payload
            != {"purpose": "single-recon-wave", "evidence": recon_state.evidence}
        ):
            raise DiscoveryViewIntegrityError("Recon source event authority disagrees")

        projection = load_verified_run_artifacts(
            self._run_path(authority.campaign, authority.projection_run_id),
            requests={authority.artifact_path: _MAX_ARTIFACT_BYTES},
            expected_run_id=authority.projection_run_id,
        )
        content = projection.artifact_bytes(authority.artifact_path)
        surface_set = AttackSurfaceSet.model_validate(
            parse_strict_json_bytes(
                content,
                label="Attack Surface Set",
                max_bytes=_MAX_ARTIFACT_BYTES,
            )
        )
        if (
            projection.verification.root_digest != authority.projection_root_digest
            or sha256(content).hexdigest() != authority.artifact_sha256
            or surface_set.campaign != authority.campaign
            or surface_set.surface_set_id != authority.surface_set_id
            or surface_set.run_id != authority.source_run_id
            or surface_set.source_root_digest != authority.source_root_digest
            or set(recon_plan.required_surface_kinds)
            - {surface.locator.kind for surface in surface_set.surfaces}
        ):
            raise DiscoveryViewIntegrityError("Surface projection authority disagrees")
        published = _single_event(projection, "discovery.attack-surface-set.published")
        request_ids = sorted({item.request_id for item in surface_set.observations})
        if (
            published.payload.get("sourceRunId") != authority.source_run_id
            or published.payload.get("sourceRootDigest") != authority.source_root_digest
            or published.payload.get("surfaceSetId") != authority.surface_set_id
            or published.payload.get("surfaceCount") != len(surface_set.surfaces)
            or published.payload.get("observationCount") != len(surface_set.observations)
            or published.payload.get("requestIds") != request_ids
            or published.payload.get("artifact") != authority.artifact_path
            or published.payload.get("surfaceSetJsonSha256")
            != sha256(surface_set.model_dump_json(by_alias=True).encode("utf-8")).hexdigest()
        ):
            raise DiscoveryViewIntegrityError("Surface publication event authority disagrees")
        return surface_set, recon_plan


def _build_view(
    *,
    hypothesis_snapshot: VerifiedRunSnapshot,
    manifest: CampaignManifest,
    hypothesis_set: AttackHypothesisSet,
    plan: HypothesisWavePlan,
    bound_plan: SurfaceBoundPlan,
    surface_set: AttackSurfaceSet,
    recon_plan: ReconWavePlan,
) -> VerifiedDiscoverySurfaceWaveView:
    authority = bound_plan.surface_snapshot
    hypotheses = {item.hypothesis_id: item for item in hypothesis_set.hypotheses}
    surfaces = {item.surface_id: item for item in surface_set.surfaces}
    if any(task.hypothesis_id not in hypotheses for task in bound_plan.tasks) or any(
        task.surface_id not in surfaces for task in bound_plan.tasks
    ):
        raise DiscoveryViewIntegrityError("Hypothesis tasks refer to unknown Surface authority")
    return VerifiedDiscoverySurfaceWaveView(
        campaign=DiscoveryCampaignView(
            name=manifest.metadata.name,
            digest=campaign_manifest_digest(manifest),
        ),
        hypothesisRun=DiscoveryRunAuthorityView(
            runId=hypothesis_snapshot.verification.run_id,
            rootDigest=hypothesis_snapshot.verification.root_digest,
        ),
        surfaceSnapshot=DiscoverySurfaceSnapshotView(
            snapshotId=authority.snapshot_id,
            snapshotDigest=authority.snapshot_digest,
            revision=authority.revision,
            surfaceSetId=authority.surface_set_id,
            sourceRunId=authority.source_run_id,
            sourceRootDigest=authority.source_root_digest,
            projectionRunId=authority.projection_run_id,
            projectionRootDigest=authority.projection_root_digest,
            artifactSha256=authority.artifact_sha256,
        ),
        surfaceSet=DiscoverySurfaceSetView(
            surfaceSetId=surface_set.surface_set_id,
            generatedAt=surface_set.generated_at,
            surfaceCount=len(surface_set.surfaces),
            observationCount=len(surface_set.observations),
            surfaces=[
                DiscoverySurfaceView(
                    surfaceId=surface.surface_id,
                    targetId=surface.target_id,
                    locator=surface.locator,
                    confidence=surface.confidence,
                    observationCount=len(surface.observation_ids),
                    firstObservedAt=surface.first_observed_at,
                    lastObservedAt=surface.last_observed_at,
                )
                for surface in surface_set.surfaces
            ],
        ),
        waves=(
            ReconWaveView(
                runId=authority.source_run_id,
                stopCondition=recon_plan.stop_condition,
                taskCount=1,
            ),
            HypothesisWaveView(
                runId=hypothesis_snapshot.verification.run_id,
                wavePlanId=plan.wave_plan_id,
                stopCondition=plan.stop_condition,
                taskCount=len(bound_plan.tasks),
                tasks=[
                    DiscoveryWaveTaskView(
                        hypothesisId=task.hypothesis_id,
                        surfaceId=task.surface_id,
                        specialistId=task.step.specialist_id,
                        threatClass=hypotheses[task.hypothesis_id].threat_class,
                    )
                    for task in bound_plan.tasks
                ],
            ),
        ),
        authorityBoundary=DiscoveryViewAuthorityBoundary(),
    )


def _strict_json(snapshot: VerifiedRunSnapshot, path: str, label: str) -> object:
    return parse_strict_json_bytes(
        snapshot.artifact_bytes(path),
        label=label,
        max_bytes=_MAX_ARTIFACT_BYTES,
    )


def _single_event(snapshot: VerifiedRunSnapshot, event_type: str) -> AuditEvent:
    matches = [event for event in snapshot.events if event.event_type == event_type]
    if len(matches) != 1:
        raise DiscoveryViewIntegrityError(f"{event_type} event is missing or ambiguous")
    return matches[0]


def _require_identifier(value: str, pattern: str, *, label: str) -> None:
    if not isinstance(value, str) or fullmatch(pattern, value) is None:
        raise ValueError(f"{label} identifier is invalid")


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())
