"""Redacted UX-004A coordinates from one durable Replay projection."""

from __future__ import annotations

from typing import Annotated, Literal, Protocol, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.control_plane.errors import ResourceNotFound, StateConflict
from pajin.control_plane.models import (
    ReplayProjectionView,
    ReplayRetestProjectionInputAuthority,
)
from pajin.domain.models import StrictModel
from pajin.domain.replay import ReplayPurpose

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_RunId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")]
_REPLAY_BATCH_PATTERN = r"^replay-batch_[0-9a-f]{32}$"
_REPLAY_PROJECTION_PATTERN = r"^replay-projection_[0-9a-f]{32}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"


class ReplayComparisonIntegrityError(ValueError):
    """Raised when a durable projection cannot support the redacted comparison."""


class _ReplayProjectionReader(Protocol):
    def get_replay_projection(self, batch_id: str) -> ReplayProjectionView | None: ...


class ReplayEvidenceCoordinateLane(StrictModel):
    """One bounded coordinate-only lane in the UX-004A comparison."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    stage: Literal["original", "replay", "control", "retest"]
    availability: Literal["verified-reference", "not-in-authority", "not-applicable"]
    authority_role: Literal[
        "original-source",
        "remediation-baseline",
        "sealed-confirmation-replay",
        "sealed-remediation-replay",
        "controls-not-bound",
        "sealed-retest-parent-and-assessment",
        "retest-not-applicable",
    ] = Field(alias="authorityRole")
    execution_count: int = Field(alias="executionCount", strict=True, ge=0, le=1_000)
    run_ids: tuple[_RunId, ...] = Field(alias="runIds", max_length=1_000)
    root_digests: tuple[_Sha256, ...] = Field(alias="rootDigests", max_length=1_000)
    evidence_digests: tuple[_Sha256, ...] = Field(
        alias="evidenceDigests",
        max_length=1_000,
    )

    @model_validator(mode="after")
    def require_exact_lane_shape(self) -> Self:
        coordinate_lengths = (
            len(self.run_ids),
            len(self.root_digests),
            len(self.evidence_digests),
        )
        if self.availability == "verified-reference":
            if self.execution_count < 1 or coordinate_lengths != (
                self.execution_count,
                self.execution_count,
                self.execution_count,
            ):
                raise ValueError("Available Replay comparison lane coordinates differ")
            if any(
                len(values) != len(set(values))
                for values in (self.run_ids, self.root_digests, self.evidence_digests)
            ):
                raise ValueError("Available Replay comparison lane coordinates must be unique")
        elif self.execution_count != 0 or any(coordinate_lengths):
            raise ValueError("Unavailable Replay comparison lanes cannot contain coordinates")
        return self


class ReplayEvidenceComparisonAuthorityBoundary(StrictModel):
    """Literal no-authority claims attached to every UX-004A response."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    durable_projection_binding_verified: Literal[True] = Field(
        default=True,
        alias="durableProjectionBindingVerified",
    )
    exact_lineage_coordinates_verified: Literal[True] = Field(
        default=True,
        alias="exactLineageCoordinatesVerified",
    )
    identifiers_and_content_redacted: Literal[True] = Field(
        default=True,
        alias="identifiersAndContentRedacted",
    )
    control_evidence_included: Literal[False] = Field(
        default=False,
        alias="controlEvidenceIncluded",
    )
    semantic_evidence_compared: Literal[False] = Field(
        default=False,
        alias="semanticEvidenceCompared",
    )
    view_evaluates_validation: Literal[False] = Field(
        default=False,
        alias="viewEvaluatesValidation",
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


class VerifiedReplayEvidenceComparisonView(StrictModel):
    """Coordinate-only Original/Replay/Control/Retest projection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.control-plane/verified-replay-evidence-comparison-view/v1alpha1"
    ] = Field(
        default="pajin.control-plane/verified-replay-evidence-comparison-view/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["VerifiedReplayEvidenceComparisonView"] = (
        "VerifiedReplayEvidenceComparisonView"
    )
    batch_id: str = Field(alias="batchId", pattern=_REPLAY_BATCH_PATTERN)
    campaign_name: str = Field(
        alias="campaignName",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    purpose: ReplayPurpose
    projection_id: str = Field(alias="projectionId", pattern=_REPLAY_PROJECTION_PATTERN)
    input_authority_digest: _Sha256 = Field(
        alias="inputAuthorityDigest",
        pattern=_SHA256_PATTERN,
    )
    projection_artifact_digest: _Sha256 = Field(
        alias="projectionArtifactDigest",
        pattern=_SHA256_PATTERN,
    )
    comparison_mode: Literal["exact-coordinates-no-semantic-diff"] = Field(
        default="exact-coordinates-no-semantic-diff",
        alias="comparisonMode",
    )
    lanes: tuple[ReplayEvidenceCoordinateLane, ...] = Field(min_length=4, max_length=4)
    authority_boundary: ReplayEvidenceComparisonAuthorityBoundary = Field(
        default_factory=ReplayEvidenceComparisonAuthorityBoundary,
        alias="authorityBoundary",
    )

    @model_validator(mode="after")
    def require_order_and_disjoint_lineage(self) -> Self:
        if tuple(lane.stage for lane in self.lanes) != (
            "original",
            "replay",
            "control",
            "retest",
        ):
            raise ValueError("Replay comparison lanes must retain canonical order")
        original, replay, control, retest = self.lanes
        if control.availability != "not-in-authority":
            raise ValueError("UX-004A cannot claim Control evidence")
        if self.purpose is ReplayPurpose.CONFIRMATION:
            if (
                original.authority_role != "original-source"
                or replay.authority_role != "sealed-confirmation-replay"
                or retest.availability != "not-applicable"
                or retest.authority_role != "retest-not-applicable"
            ):
                raise ValueError("Confirmation comparison lane roles differ")
        elif (
            original.authority_role != "remediation-baseline"
            or replay.authority_role != "sealed-remediation-replay"
            or retest.availability != "verified-reference"
            or retest.authority_role != "sealed-retest-parent-and-assessment"
        ):
            raise ValueError("Remediation Retest comparison lane roles differ")
        available = tuple(lane for lane in self.lanes if lane.availability == "verified-reference")
        for attribute in ("run_ids", "root_digests"):
            values = tuple(value for lane in available for value in getattr(lane, attribute))
            if len(values) != len(set(values)):
                raise ValueError("Replay comparison lineages must be pairwise disjoint")
        return self


class VerifiedReplayEvidenceComparisonReader:
    """Build one redacted comparison from the existing durable projection reader."""

    def __init__(self, projection_reader: _ReplayProjectionReader) -> None:
        self._projection_reader = projection_reader

    def read(self, *, batch_id: str) -> VerifiedReplayEvidenceComparisonView:
        try:
            projection = self._projection_reader.get_replay_projection(batch_id)
            if projection is None:
                raise ResourceNotFound("Replay comparison projection was not found")
            canonical = ReplayProjectionView.model_validate(
                projection.model_dump(mode="json", by_alias=True)
            )
            authority = canonical.input_authority
            is_retest = isinstance(authority, ReplayRetestProjectionInputAuthority)
            if is_retest != (canonical.batch.purpose is ReplayPurpose.REMEDIATION_RETEST):
                raise ValueError("Replay comparison purpose and authority version differ")

            original = ReplayEvidenceCoordinateLane(
                stage="original",
                availability="verified-reference",
                authorityRole="remediation-baseline" if is_retest else "original-source",
                executionCount=1,
                runIds=(authority.source.run_id,),
                rootDigests=(authority.source.integrity_root_digest,),
                evidenceDigests=(authority.source.content_digest,),
            )
            replay = ReplayEvidenceCoordinateLane(
                stage="replay",
                availability="verified-reference",
                authorityRole=(
                    "sealed-remediation-replay" if is_retest else "sealed-confirmation-replay"
                ),
                executionCount=len(authority.items),
                runIds=tuple(item.replay_run_id for item in authority.items),
                rootDigests=tuple(item.receipt_seal_root_digest for item in authority.items),
                evidenceDigests=tuple(item.result_digest for item in authority.items),
            )
            control = ReplayEvidenceCoordinateLane(
                stage="control",
                availability="not-in-authority",
                authorityRole="controls-not-bound",
                executionCount=0,
                runIds=(),
                rootDigests=(),
                evidenceDigests=(),
            )
            if is_retest:
                assert isinstance(authority, ReplayRetestProjectionInputAuthority)
                retest = ReplayEvidenceCoordinateLane(
                    stage="retest",
                    availability="verified-reference",
                    authorityRole="sealed-retest-parent-and-assessment",
                    executionCount=1,
                    runIds=(authority.retest_source.run_id,),
                    rootDigests=(authority.retest_source.integrity_root_digest,),
                    evidenceDigests=(canonical.artifact.content_digest,),
                )
            else:
                retest = ReplayEvidenceCoordinateLane(
                    stage="retest",
                    availability="not-applicable",
                    authorityRole="retest-not-applicable",
                    executionCount=0,
                    runIds=(),
                    rootDigests=(),
                    evidenceDigests=(),
                )
            return VerifiedReplayEvidenceComparisonView(
                batchId=canonical.batch.batch_id,
                campaignName=canonical.batch.campaign_name,
                purpose=canonical.batch.purpose,
                projectionId=canonical.projection_id,
                inputAuthorityDigest=canonical.input_authority_digest,
                projectionArtifactDigest=canonical.artifact.content_digest,
                lanes=(original, replay, control, retest),
            )
        except ResourceNotFound:
            raise
        except (AttributeError, StateConflict, TypeError, ValidationError, ValueError) as exc:
            raise ReplayComparisonIntegrityError(
                "Replay comparison authority is not integrity-valid"
            ) from exc
