"""UX-004B redacted comparison over one exact sealed VAL-004C authority."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.canonicalization import discovery_digest
from pajin.discovery.walking_mcp import (
    MCPToolAuthorizationHypothesisAuthority,
    MCPToolAuthorizationHypothesisOutcome,
)
from pajin.discovery.walking_replay import (
    WalkingMCPClaimReplayAuthority,
    WalkingMCPClaimReplayOutcome,
)
from pajin.discovery.walking_validation import WalkingExecutionEvidence
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.domain.validation_controls import ValidationControlContrast, ValidationControlKind
from pajin.runtime.safe_files import (
    atomic_write_text_no_follow,
    load_bounded_strict_json,
    parse_strict_json_bytes,
)
from pajin.runtime.store import RunIntegrityError, load_verified_run_artifacts
from pajin.workflow.mode_neutral_profile_evidence import (
    ModeNeutralClaimControlAuthority,
    ModeNeutralClaimControlOutcome,
)
from pajin.workflow.mode_neutral_repeated_profile_evidence import (
    ModeNeutralRepeatedProfileEvidenceError,
    ModeNeutralRepeatedProfileValidationEvidenceAssessment,
    verify_mode_neutral_repeated_profile_validation_evidence,
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_COMPARISON_ID_PATTERN = r"^walking-control-comparison_[a-f0-9]{64}$"
_COMPARISON_ARTIFACT = "comparison.json"
_COMPARISON_ROOT = "comparisons"
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_MAX_ARTIFACT_NODES = 500_000
_MAX_PATH_LENGTH = 2_000
_CONTROL_KINDS = tuple(ValidationControlKind)
_CoordinateRole = Literal[
    "original-source",
    "primary-replay",
    "additional-replay",
    "baseline-control",
    "negative-control",
    "counterfactual-control",
]


class WalkingControlComparisonUnavailable(RuntimeError):
    """Raised when no server-owned VAL-004C evidence root is configured."""


class WalkingControlComparisonNotFound(RuntimeError):
    """Raised when one exact comparison locator does not exist."""


class WalkingControlComparisonIntegrityError(ValueError):
    """Raised when a locator or any sealed VAL-004C predecessor is invalid."""


class WalkingControlComparisonArtifactError(ValueError):
    """Raised when a verified locator cannot be written and read back exactly."""


def _canonical_relative_path(value: str, *, label: str) -> str:
    if not value or len(value) > _MAX_PATH_LENGTH or "\\" in value:
        raise ValueError(f"{label} must be a bounded canonical relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ValueError(f"{label} must be a bounded canonical relative path")
    return value


class WalkingComparisonRunLocator(StrictModel):
    """One server-root-relative sealed publication Run reference."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    relative_path: str = Field(alias="relativePath", min_length=1, max_length=_MAX_PATH_LENGTH)
    artifact_path: str = Field(alias="artifactPath", min_length=1, max_length=_MAX_PATH_LENGTH)

    @field_validator("relative_path", mode="before")
    @classmethod
    def require_relative_run_path(cls, value: object) -> object:
        if not isinstance(value, str):
            raise ValueError("Run path must be canonical text")
        return _canonical_relative_path(value, label="Run path")

    @field_validator("artifact_path", mode="before")
    @classmethod
    def require_relative_artifact_path(cls, value: object) -> object:
        if not isinstance(value, str):
            raise ValueError("Artifact path must be canonical text")
        return _canonical_relative_path(value, label="Artifact path")


class WalkingControlExecutionRunLocator(StrictModel):
    """One exact Control execution Run path, ordered by canonical Control kind."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    control_kind: ValidationControlKind = Field(alias="controlKind")
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    relative_path: str = Field(alias="relativePath", min_length=1, max_length=_MAX_PATH_LENGTH)

    @field_validator("relative_path", mode="before")
    @classmethod
    def require_relative_run_path(cls, value: object) -> object:
        if not isinstance(value, str):
            raise ValueError("Control execution path must be canonical text")
        return _canonical_relative_path(value, label="Control execution path")


class WalkingControlComparisonLocator(StrictModel):
    """Content-addressed locator that adds no evidence or validation authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.control-plane/walking-control-comparison-locator/v1alpha1"
    ] = Field(
        default="pajin.control-plane/walking-control-comparison-locator/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["WalkingControlComparisonLocator"] = "WalkingControlComparisonLocator"
    comparison_id: str = Field(default="", alias="comparisonId", max_length=128)
    comparison_digest: str = Field(default="", alias="comparisonDigest", max_length=64)
    assessment: ModeNeutralRepeatedProfileValidationEvidenceAssessment
    chain_source: WalkingComparisonRunLocator = Field(alias="chainSource")
    primary_replay: WalkingComparisonRunLocator = Field(alias="primaryReplay")
    additional_replay: WalkingComparisonRunLocator = Field(alias="additionalReplay")
    control_publication: WalkingComparisonRunLocator = Field(alias="controlPublication")
    control_executions: tuple[WalkingControlExecutionRunLocator, ...] = Field(
        alias="controlExecutions",
        min_length=3,
        max_length=3,
    )
    source_authority: Literal["val-004c-repeated-walking-mcp-v1"] = Field(
        default="val-004c-repeated-walking-mcp-v1",
        alias="sourceAuthority",
    )

    @model_validator(mode="after")
    def bind_locator(self) -> Self:
        repeated = self.assessment.repeated_claim_replay
        controls = self.assessment.control_evidence
        control_kinds = tuple(item.control_kind for item in self.control_executions)
        execution_run_ids = tuple(item.run_id for item in self.control_executions)
        if (
            self.primary_replay.run_id != repeated.claim_replays[0].replay.run_id
            or self.additional_replay.run_id != repeated.claim_replays[1].replay.run_id
            or control_kinds != _CONTROL_KINDS
            or execution_run_ids
            != tuple(item.execution.run_id for item in controls.executions)
        ):
            raise ValueError("VAL-004C comparison locator differs from its assessment")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"comparison_id", "comparison_digest"},
        )
        digest = discovery_digest(
            "pajin.control-plane.walking-control-comparison-locator/v1",
            material,
        )
        comparison_id = f"walking-control-comparison_{digest}"
        if self.comparison_digest and self.comparison_digest != digest:
            raise ValueError("Walking Control comparison locator Digest differs")
        if self.comparison_id and self.comparison_id != comparison_id:
            raise ValueError("Walking Control comparison locator ID differs")
        object.__setattr__(self, "comparison_digest", digest)
        object.__setattr__(self, "comparison_id", comparison_id)
        return self


class WalkingControlComparisonCoordinate(StrictModel):
    """One redacted exact execution coordinate from the verified VAL-004C assessment."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    ordinal: int = Field(strict=True, ge=0, le=5)
    role: _CoordinateRole
    control_kind: ValidationControlKind | None = Field(default=None, alias="controlKind")
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    root_digest: _Sha256 = Field(alias="rootDigest")
    execution_digest: _Sha256 = Field(alias="executionDigest")


class WalkingControlComparisonLane(StrictModel):
    """One canonical Original, Replay, Control, or unavailable Retest lane."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    stage: Literal["original", "replay", "control", "retest"]
    availability: Literal["verified-reference", "not-in-authority"]
    authority_role: Literal[
        "sealed-source-execution",
        "sealed-repeated-validity-replay",
        "sealed-baseline-negative-counterfactual",
        "retest-not-bound",
    ] = Field(alias="authorityRole")
    execution_count: int = Field(alias="executionCount", strict=True, ge=0, le=3)
    coordinates: tuple[WalkingControlComparisonCoordinate, ...] = Field(max_length=3)

    @model_validator(mode="after")
    def require_exact_lane(self) -> Self:
        expected = {
            "original": ("verified-reference", "sealed-source-execution", (0,)),
            "replay": ("verified-reference", "sealed-repeated-validity-replay", (1, 2)),
            "control": (
                "verified-reference",
                "sealed-baseline-negative-counterfactual",
                (3, 4, 5),
            ),
            "retest": ("not-in-authority", "retest-not-bound", ()),
        }[self.stage]
        ordinals = tuple(item.ordinal for item in self.coordinates)
        if (
            self.availability != expected[0]
            or self.authority_role != expected[1]
            or ordinals != expected[2]
            or self.execution_count != len(self.coordinates)
        ):
            raise ValueError("Walking Control comparison lane shape differs")
        if self.stage == "control":
            if tuple(item.control_kind for item in self.coordinates) != _CONTROL_KINDS:
                raise ValueError("Walking Control comparison Control order differs")
        elif any(item.control_kind is not None for item in self.coordinates):
            raise ValueError("Non-Control comparison coordinates cannot name a Control kind")
        return self


class WalkingControlComparisonAuthorityBoundary(StrictModel):
    """Literal authority ceiling attached to every UX-004B response."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    val004c_sealed_predecessors_verified: Literal[True] = Field(
        default=True,
        alias="val004cSealedPredecessorsVerified",
    )
    exact_execution_lineage_verified: Literal[True] = Field(
        default=True,
        alias="exactExecutionLineageVerified",
    )
    control_contrast_verified: Literal[True] = Field(
        default=True,
        alias="controlContrastVerified",
    )
    identifiers_and_content_redacted: Literal[True] = Field(
        default=True,
        alias="identifiersAndContentRedacted",
    )
    retest_evidence_included: Literal[False] = Field(
        default=False,
        alias="retestEvidenceIncluded",
    )
    view_creates_validation_assessment: Literal[False] = Field(
        default=False,
        alias="viewCreatesValidationAssessment",
    )
    view_attests_profile_selection: Literal[False] = Field(
        default=False,
        alias="viewAttestsProfileSelection",
    )
    view_attests_remediation: Literal[False] = Field(
        default=False,
        alias="viewAttestsRemediation",
    )
    view_confirms_finding: Literal[False] = Field(
        default=False,
        alias="viewConfirmsFinding",
    )
    view_authorizes_execution: Literal[False] = Field(
        default=False,
        alias="viewAuthorizesExecution",
    )

    @field_validator(
        "val004c_sealed_predecessors_verified",
        "exact_execution_lineage_verified",
        "control_contrast_verified",
        "identifiers_and_content_redacted",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Walking Control comparison verification markers must be true")
        return value

    @field_validator(
        "retest_evidence_included",
        "view_creates_validation_assessment",
        "view_attests_profile_selection",
        "view_attests_remediation",
        "view_confirms_finding",
        "view_authorizes_execution",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Walking Control comparison authority markers must be false")
        return value


class VerifiedWalkingControlComparisonView(StrictModel):
    """Redacted Original, repeated Replay, and exact three-Control comparison."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.control-plane/verified-walking-control-comparison-view/v1alpha1"
    ] = Field(
        default="pajin.control-plane/verified-walking-control-comparison-view/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["VerifiedWalkingControlComparisonView"] = (
        "VerifiedWalkingControlComparisonView"
    )
    comparison_id: str = Field(alias="comparisonId", pattern=_COMPARISON_ID_PATTERN)
    comparison_digest: _Sha256 = Field(alias="comparisonDigest")
    assessment_digest: _Sha256 = Field(alias="assessmentDigest")
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    claim_digest: _Sha256 = Field(alias="claimDigest")
    profile_id: str = Field(alias="profileId", min_length=1, max_length=200)
    profile_version: str = Field(alias="profileVersion", min_length=1, max_length=50)
    achieved_depth: Literal["repeated-controlled-validity-replay"] = Field(
        alias="achievedDepth"
    )
    validation_state: Literal["profile-floor-satisfied-not-confirmed"] = Field(
        alias="validationState"
    )
    control_contrast: Literal[ValidationControlContrast.OBSERVED] = Field(
        alias="controlContrast"
    )
    comparison_mode: Literal[
        "exact-execution-coordinates-with-verified-control-contrast"
    ] = Field(
        default="exact-execution-coordinates-with-verified-control-contrast",
        alias="comparisonMode",
    )
    lanes: tuple[WalkingControlComparisonLane, ...] = Field(min_length=4, max_length=4)
    authority_boundary: WalkingControlComparisonAuthorityBoundary = Field(
        default_factory=WalkingControlComparisonAuthorityBoundary,
        alias="authorityBoundary",
    )

    @model_validator(mode="after")
    def require_canonical_comparison(self) -> Self:
        if tuple(lane.stage for lane in self.lanes) != (
            "original",
            "replay",
            "control",
            "retest",
        ):
            raise ValueError("Walking Control comparison lanes must retain canonical order")
        coordinates = tuple(item for lane in self.lanes for item in lane.coordinates)
        if tuple(item.ordinal for item in coordinates) != tuple(range(6)):
            raise ValueError("Walking Control comparison coordinates must retain exact order")
        for attribute in ("run_id", "root_digest", "execution_digest"):
            values = tuple(getattr(item, attribute) for item in coordinates)
            if len(values) != len(set(values)):
                raise ValueError("Walking Control comparison execution lineages must be disjoint")
        return self


@dataclass(frozen=True, slots=True)
class WalkingControlComparisonArtifact:
    path: Path
    locator: WalkingControlComparisonLocator
    view: VerifiedWalkingControlComparisonView


@dataclass(frozen=True, slots=True)
class _WalkingComparisonDependencies:
    campaign: CampaignManifest
    chain_source: MCPToolAuthorizationHypothesisOutcome
    primary_replay: WalkingMCPClaimReplayOutcome
    additional_replay: WalkingMCPClaimReplayOutcome
    controls: ModeNeutralClaimControlOutcome


class VerifiedWalkingControlComparisonReader:
    """Reopen one locator and every exact sealed VAL-004C predecessor."""

    def __init__(self, root: Path | None) -> None:
        self._root = _validated_root(root) if root is not None else None

    def read(self, *, comparison_id: str) -> VerifiedWalkingControlComparisonView:
        if self._root is None:
            raise WalkingControlComparisonUnavailable(
                "VAL-004C comparison evidence root is not configured"
            )
        if not _is_comparison_id(comparison_id):
            raise WalkingControlComparisonNotFound(
                "Walking Control comparison was not found"
            )
        path = self._root / _COMPARISON_ROOT / comparison_id / _COMPARISON_ARTIFACT
        try:
            _require_lookup_artifact_exists(
                self._root,
                comparison_id=comparison_id,
                artifact_path=path,
            )
            decoded = load_bounded_strict_json(
                path,
                max_bytes=_MAX_ARTIFACT_BYTES,
                label="Walking Control comparison locator",
                require_single_link=True,
                max_depth=128,
                max_nodes=_MAX_ARTIFACT_NODES,
            )
            locator = WalkingControlComparisonLocator.model_validate(decoded)
            if locator.comparison_id != comparison_id:
                raise ValueError("Walking Control comparison key differs from locator")
            dependencies = _load_dependencies(self._root, locator)
            assessment = verify_mode_neutral_repeated_profile_validation_evidence(
                locator.assessment,
                dependencies.campaign,
                dependencies.chain_source,
                dependencies.primary_replay,
                dependencies.additional_replay,
                dependencies.controls,
            )
            if assessment != locator.assessment:
                raise ValueError("Walking Control comparison assessment differs")
            return _comparison_view(locator, assessment)
        except FileNotFoundError as exc:
            raise WalkingControlComparisonNotFound(
                "Walking Control comparison was not found"
            ) from exc
        except WalkingControlComparisonNotFound:
            raise
        except (
            AttributeError,
            KeyError,
            ModeNeutralRepeatedProfileEvidenceError,
            OSError,
            RunIntegrityError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise WalkingControlComparisonIntegrityError(
                "Walking Control comparison authority is not integrity-valid"
            ) from exc


def _require_lookup_artifact_exists(
    root: Path,
    *,
    comparison_id: str,
    artifact_path: Path,
) -> None:
    """Distinguish an absent lookup key from malformed existing path material."""

    for candidate in (
        root / _COMPARISON_ROOT,
        root / _COMPARISON_ROOT / comparison_id,
        artifact_path,
    ):
        try:
            candidate.lstat()
        except FileNotFoundError as exc:
            raise WalkingControlComparisonNotFound(
                "Walking Control comparison was not found"
            ) from exc
        except OSError:
            # The secure bounded reader remains authoritative for inaccessible,
            # non-directory, link, junction, and raced path material.
            return
        if candidate.is_symlink() or candidate.is_junction():
            return
        if candidate != artifact_path and not candidate.is_dir():
            return


def write_walking_control_comparison_locator(
    *,
    root: Path,
    assessment: ModeNeutralRepeatedProfileValidationEvidenceAssessment,
    campaign: CampaignManifest,
    chain_source: MCPToolAuthorizationHypothesisOutcome,
    primary_replay: WalkingMCPClaimReplayOutcome,
    additional_replay: WalkingMCPClaimReplayOutcome,
    controls: ModeNeutralClaimControlOutcome,
) -> WalkingControlComparisonArtifact:
    """Verify and persist one content-addressed, server-root-relative locator."""

    try:
        evidence_root = _validated_root(root)
        verified = verify_mode_neutral_repeated_profile_validation_evidence(
            assessment,
            campaign,
            chain_source,
            primary_replay,
            additional_replay,
            controls,
        )
        control_paths = tuple(item.run_path for item in controls.execution_evidence)
        locator = WalkingControlComparisonLocator(
            assessment=verified,
            chainSource=_run_locator(evidence_root, chain_source),
            primaryReplay=_run_locator(evidence_root, primary_replay),
            additionalReplay=_run_locator(evidence_root, additional_replay),
            controlPublication=_run_locator(evidence_root, controls),
            controlExecutions=tuple(
                WalkingControlExecutionRunLocator(
                    controlKind=execution.definition.control_kind,
                    runId=execution.execution.run_id,
                    relativePath=_relative_run_path(evidence_root, run_path),
                )
                for execution, run_path in zip(
                    verified.control_evidence.executions,
                    control_paths,
                    strict=True,
                )
            ),
        )
        content = (
            json.dumps(
                locator.model_dump(mode="json", by_alias=True),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        if len(content.encode("utf-8")) > _MAX_ARTIFACT_BYTES:
            raise ValueError("Walking Control comparison locator exceeds its byte limit")
        path = (
            evidence_root
            / _COMPARISON_ROOT
            / locator.comparison_id
            / _COMPARISON_ARTIFACT
        )
        atomic_write_text_no_follow(
            path,
            content,
            label="Walking Control comparison locator",
        )
        view = VerifiedWalkingControlComparisonReader(evidence_root).read(
            comparison_id=locator.comparison_id
        )
        return WalkingControlComparisonArtifact(path=path, locator=locator, view=view)
    except WalkingControlComparisonArtifactError:
        raise
    except (
        AttributeError,
        ModeNeutralRepeatedProfileEvidenceError,
        OSError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise WalkingControlComparisonArtifactError(
            "Walking Control comparison locator write failed"
        ) from exc


def _load_dependencies(
    root: Path,
    locator: WalkingControlComparisonLocator,
) -> _WalkingComparisonDependencies:
    chain_path = _resolve_run_path(root, locator.chain_source.relative_path)
    chain_snapshot = load_verified_run_artifacts(
        chain_path,
        requests={
            "campaign.json": _MAX_ARTIFACT_BYTES,
            locator.chain_source.artifact_path: _MAX_ARTIFACT_BYTES,
        },
        expected_run_id=locator.chain_source.run_id,
    )
    campaign = CampaignManifest.model_validate_json(
        chain_snapshot.artifact_bytes("campaign.json")
    )
    raw_hypotheses = parse_strict_json_bytes(
        chain_snapshot.artifact_bytes(locator.chain_source.artifact_path),
        label="Walking Control comparison Chain source",
        max_bytes=_MAX_ARTIFACT_BYTES,
    )
    if not isinstance(raw_hypotheses, list) or not raw_hypotheses:
        raise ValueError("Walking Control comparison Chain source must be a non-empty array")
    chain_source = MCPToolAuthorizationHypothesisOutcome(
        run_id=locator.chain_source.run_id,
        run_path=chain_path,
        artifact_path=locator.chain_source.artifact_path,
        hypotheses=tuple(
            MCPToolAuthorizationHypothesisAuthority.model_validate(item)
            for item in raw_hypotheses
        ),
    )
    primary = _load_replay_outcome(root, locator.primary_replay)
    additional = _load_replay_outcome(root, locator.additional_replay)
    controls = _load_control_outcome(root, locator)
    return _WalkingComparisonDependencies(
        campaign=campaign,
        chain_source=chain_source,
        primary_replay=primary,
        additional_replay=additional,
        controls=controls,
    )


def _load_replay_outcome(
    root: Path,
    locator: WalkingComparisonRunLocator,
) -> WalkingMCPClaimReplayOutcome:
    run_path = _resolve_run_path(root, locator.relative_path)
    snapshot = load_verified_run_artifacts(
        run_path,
        requests={locator.artifact_path: _MAX_ARTIFACT_BYTES},
        expected_run_id=locator.run_id,
    )
    authority = WalkingMCPClaimReplayAuthority.model_validate_json(
        snapshot.artifact_bytes(locator.artifact_path)
    )
    return WalkingMCPClaimReplayOutcome(
        run_id=locator.run_id,
        run_path=run_path,
        artifact_path=locator.artifact_path,
        authority=authority,
    )


def _load_control_outcome(
    root: Path,
    locator: WalkingControlComparisonLocator,
) -> ModeNeutralClaimControlOutcome:
    publication = locator.control_publication
    run_path = _resolve_run_path(root, publication.relative_path)
    snapshot = load_verified_run_artifacts(
        run_path,
        requests={publication.artifact_path: _MAX_ARTIFACT_BYTES},
        expected_run_id=publication.run_id,
    )
    authority = ModeNeutralClaimControlAuthority.model_validate_json(
        snapshot.artifact_bytes(publication.artifact_path)
    )
    execution_evidence = tuple(
        WalkingExecutionEvidence(
            run_path=_resolve_run_path(root, run_locator.relative_path),
            grant=execution.execution.grant,
            permit=execution.execution.permit,
            request=execution.execution.request,
            intent=execution.execution.approval.intent,
            approval=execution.execution.approval.approval,
        )
        for execution, run_locator in zip(
            authority.executions,
            locator.control_executions,
            strict=True,
        )
    )
    return ModeNeutralClaimControlOutcome(
        run_id=publication.run_id,
        run_path=run_path,
        artifact_path=publication.artifact_path,
        authority=authority,
        execution_evidence=execution_evidence,
    )


def _comparison_view(
    locator: WalkingControlComparisonLocator,
    assessment: ModeNeutralRepeatedProfileValidationEvidenceAssessment,
) -> VerifiedWalkingControlComparisonView:
    independence = assessment.independence
    roles: tuple[_CoordinateRole, ...] = (
        "original-source",
        "primary-replay",
        "additional-replay",
        "baseline-control",
        "negative-control",
        "counterfactual-control",
    )
    control_kinds: tuple[ValidationControlKind | None, ...] = (
        None,
        None,
        None,
        *_CONTROL_KINDS,
    )
    coordinates = tuple(
        WalkingControlComparisonCoordinate(
            ordinal=index,
            role=roles[index],
            controlKind=control_kinds[index],
            runId=independence.execution_run_ids[index],
            rootDigest=independence.root_digests[index],
            executionDigest=independence.execution_digests[index],
        )
        for index in range(6)
    )
    lanes = (
        WalkingControlComparisonLane(
            stage="original",
            availability="verified-reference",
            authorityRole="sealed-source-execution",
            executionCount=1,
            coordinates=coordinates[0:1],
        ),
        WalkingControlComparisonLane(
            stage="replay",
            availability="verified-reference",
            authorityRole="sealed-repeated-validity-replay",
            executionCount=2,
            coordinates=coordinates[1:3],
        ),
        WalkingControlComparisonLane(
            stage="control",
            availability="verified-reference",
            authorityRole="sealed-baseline-negative-counterfactual",
            executionCount=3,
            coordinates=coordinates[3:6],
        ),
        WalkingControlComparisonLane(
            stage="retest",
            availability="not-in-authority",
            authorityRole="retest-not-bound",
            executionCount=0,
            coordinates=(),
        ),
    )
    replay = assessment.repeated_claim_replay
    return VerifiedWalkingControlComparisonView(
        comparisonId=locator.comparison_id,
        comparisonDigest=locator.comparison_digest,
        assessmentDigest=assessment.assessment_digest,
        campaignDigest=replay.campaign_digest,
        claimDigest=assessment.claim.claim_digest,
        profileId=assessment.profile_floor.profile_id,
        profileVersion=assessment.profile_floor.profile_version,
        achievedDepth="repeated-controlled-validity-replay",
        validationState=assessment.validation_state,
        controlContrast=assessment.control_evidence.contrast,
        lanes=lanes,
    )


def _run_locator(
    root: Path,
    outcome: MCPToolAuthorizationHypothesisOutcome
    | WalkingMCPClaimReplayOutcome
    | ModeNeutralClaimControlOutcome,
) -> WalkingComparisonRunLocator:
    return WalkingComparisonRunLocator(
        runId=outcome.run_id,
        relativePath=_relative_run_path(root, outcome.run_path),
        artifactPath=outcome.artifact_path,
    )


def _relative_run_path(root: Path, run_path: Path) -> str:
    resolved = _resolve_existing_directory(run_path)
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("Walking Control comparison Run is outside its evidence root") from exc
    return _canonical_relative_path(relative, label="Run path")


def _resolve_run_path(root: Path, relative_path: str) -> Path:
    relative = _canonical_relative_path(relative_path, label="Run path")
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    resolved = _resolve_existing_directory(candidate)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Walking Control comparison Run escaped its evidence root") from exc
    return resolved


def _validated_root(root: Path) -> Path:
    resolved = _resolve_existing_directory(root)
    if resolved != root.resolve(strict=True):
        raise ValueError("Walking Control comparison root is not canonical")
    return resolved


def _resolve_existing_directory(path: Path) -> Path:
    candidate = path.absolute()
    try:
        if _is_link(candidate):
            raise ValueError("Walking Control comparison path cannot be a link")
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError("Walking Control comparison directory is unavailable") from exc
    if not resolved.is_dir() or _is_link(resolved) or resolved != candidate:
        raise ValueError("Walking Control comparison path must be a canonical directory")
    return resolved


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _is_comparison_id(value: str) -> bool:
    if len(value) != len("walking-control-comparison_") + 64:
        return False
    prefix, digest = value.rsplit("_", 1)
    return prefix == "walking-control-comparison" and all(
        character in "0123456789abcdef" for character in digest
    )
