"""VAL-002 mode-neutral Validation depth requirement policy."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.domain.models import StrictModel
from pajin.domain.replay import ReplaySessionPolicy
from pajin.domain.validation import AtomicClaimType, ClaimReplayStatus
from pajin.domain.validation_controls import (
    ValidationControlContrast,
    ValidationControlKind,
)

VALIDATION_DEPTH_POLICY_API_VERSION: Literal["pajin.dev/validation-depth-policy/v1alpha1"] = (
    "pajin.dev/validation-depth-policy/v1alpha1"
)

_CONTROL_KINDS = tuple(ValidationControlKind)
_SUPPORTED_CLAIM_TYPES = (AtomicClaimType.VALIDITY,)
_ISOLATED_REPLAY_SESSION_POLICIES = (
    ReplaySessionPolicy.FRESH_SESSION,
    ReplaySessionPolicy.STATELESS,
)
_MAX_POLICY_BYTES = 128 * 1024


class ValidationDepthPolicyError(ValueError):
    """Raised when a Validation depth is not part of the code-owned policy."""


class ValidationDepth(StrEnum):
    """Ordered evidence requirement levels; none grants evidence or execution authority."""

    SINGLE_VALIDITY_REPLAY = "single-validity-replay"
    CONTROLLED_VALIDITY_REPLAY = "controlled-validity-replay"
    REPEATED_CONTROLLED_VALIDITY_REPLAY = "repeated-controlled-validity-replay"


class ValidationDepthRequirement(StrictModel):
    """One immutable requirement level without evidence-satisfaction authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    depth: ValidationDepth
    depth_ordinal: int = Field(alias="depthOrdinal", ge=1, le=3)
    requirement_digest: str = Field(default="", alias="requirementDigest", max_length=64)
    required_claim_types: tuple[AtomicClaimType, ...] = Field(
        alias="requiredClaimTypes",
        min_length=1,
        max_length=1,
    )
    required_claim_replay_status: Literal[ClaimReplayStatus.REPRODUCED] = Field(
        default=ClaimReplayStatus.REPRODUCED,
        alias="requiredClaimReplayStatus",
    )
    minimum_replay_repetitions: int = Field(
        alias="minimumReplayRepetitions",
        ge=1,
        le=20,
    )
    required_control_kinds: tuple[ValidationControlKind, ...] = Field(
        alias="requiredControlKinds",
        max_length=3,
    )
    minimum_control_executions_per_kind: int = Field(
        alias="minimumControlExecutionsPerKind",
        ge=0,
        le=20,
    )
    required_control_contrast: ValidationControlContrast | None = Field(
        alias="requiredControlContrast",
    )
    independence_scope: Literal["fresh-execution-lineage"] = Field(
        default="fresh-execution-lineage",
        alias="independenceScope",
    )
    allowed_replay_session_policies: tuple[ReplaySessionPolicy, ...] = Field(
        default=_ISOLATED_REPLAY_SESSION_POLICIES,
        alias="allowedReplaySessionPolicies",
        min_length=2,
        max_length=2,
    )
    replay_session_isolation_required: Literal[True] = Field(
        default=True,
        alias="replaySessionIsolationRequired",
    )
    fresh_capability_per_execution_required: Literal[True] = Field(
        default=True,
        alias="freshCapabilityPerExecutionRequired",
    )
    distinct_request_per_execution_required: Literal[True] = Field(
        default=True,
        alias="distinctRequestPerExecutionRequired",
    )
    evidence_lineage_required: Literal[True] = Field(
        default=True,
        alias="evidenceLineageRequired",
    )
    policy_only: Literal[True] = Field(default=True, alias="policyOnly")
    evidence_evaluation_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceEvaluationAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )
    confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="confirmationAuthorized",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator(
        "replay_session_isolation_required",
        "fresh_capability_per_execution_required",
        "distinct_request_per_execution_required",
        "evidence_lineage_required",
        "policy_only",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Validation depth requirement markers must be boolean true")
        return value

    @field_validator(
        "evidence_evaluation_authorized",
        "execution_authorized",
        "confirmation_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Validation depth authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_requirement_identity(self) -> Self:
        if self.required_claim_types != _SUPPORTED_CLAIM_TYPES:
            raise ValueError("VAL-002 v1 supports only the validity Claim type")
        if self.allowed_replay_session_policies != _ISOLATED_REPLAY_SESSION_POLICIES:
            raise ValueError(
                "VAL-002 requires an isolated fresh-session or stateless Replay policy"
            )
        if not self.required_control_kinds:
            if (
                self.minimum_control_executions_per_kind != 0
                or self.required_control_contrast is not None
            ):
                raise ValueError("Control-free depth cannot require Control evidence")
        elif (
            self.required_control_kinds != _CONTROL_KINDS
            or self.minimum_control_executions_per_kind < 1
            or self.required_control_contrast is not ValidationControlContrast.OBSERVED
        ):
            raise ValueError("Controlled depth requires the exact three-Control contrast")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"requirement_digest"},
        )
        digest = discovery_digest(
            "pajin.validation.validation-depth-requirement/v1",
            material,
        )
        if self.requirement_digest and self.requirement_digest != digest:
            raise ValueError("Validation depth Requirement Digest differs")
        object.__setattr__(self, "requirement_digest", digest)
        return self


class ValidationDepthPolicy(StrictModel):
    """Exact code-owned requirement catalog without Profile or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/validation-depth-policy/v1alpha1"] = Field(
        default=VALIDATION_DEPTH_POLICY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ValidationDepthPolicy"] = "ValidationDepthPolicy"
    policy_id: Literal["val-002:validation-depth-policy"] = Field(
        default="val-002:validation-depth-policy",
        alias="policyId",
    )
    policy_version: Literal["1.0.0"] = Field(default="1.0.0", alias="policyVersion")
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    supported_claim_types: tuple[AtomicClaimType, ...] = Field(
        default=_SUPPORTED_CLAIM_TYPES,
        alias="supportedClaimTypes",
        min_length=1,
        max_length=1,
    )
    replay_repetition_ceiling: Literal[20] = Field(
        default=20,
        alias="replayRepetitionCeiling",
    )
    requirements: tuple[ValidationDepthRequirement, ...] = Field(
        min_length=3,
        max_length=3,
    )
    profile_assurance_floor_bound: Literal[False] = Field(
        default=False,
        alias="profileAssuranceFloorBound",
    )
    evidence_evaluation_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceEvaluationAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )
    confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="confirmationAuthorized",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator(
        "profile_assurance_floor_bound",
        "evidence_evaluation_authorized",
        "execution_authorized",
        "confirmation_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Validation depth Policy authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> Self:
        expected = _validation_depth_requirements()
        if self.supported_claim_types != _SUPPORTED_CLAIM_TYPES:
            raise ValueError("Validation depth supported Claim types differ")
        if self.requirements != expected:
            raise ValueError("Validation depth requirements differ from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_digest"},
        )
        digest = discovery_digest(
            "pajin.validation.validation-depth-policy/v1",
            material,
        )
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Validation Depth Policy Digest differs")
        object.__setattr__(self, "policy_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Validation Depth Policy",
            max_bytes=_MAX_POLICY_BYTES,
        )
        return self


def registered_validation_depth_policy() -> ValidationDepthPolicy:
    """Return the exact mode-neutral VAL-002 requirement catalog."""

    return ValidationDepthPolicy(requirements=_validation_depth_requirements())


def resolve_validation_depth_requirement(
    depth: ValidationDepth | str,
) -> ValidationDepthRequirement:
    """Resolve one exact depth; aliases and latest-version fallback are not supported."""

    try:
        canonical_depth = ValidationDepth(depth)
        for requirement in registered_validation_depth_policy().requirements:
            if requirement.depth is canonical_depth:
                return requirement.model_copy(deep=True)
    except (TypeError, ValidationError, ValueError) as exc:
        raise ValidationDepthPolicyError("Validation depth is not registered") from exc
    raise ValidationDepthPolicyError("Validation depth is not registered")


def _validation_depth_requirements() -> tuple[ValidationDepthRequirement, ...]:
    specs = (
        (
            ValidationDepth.SINGLE_VALIDITY_REPLAY,
            1,
            1,
            (),
            0,
            None,
        ),
        (
            ValidationDepth.CONTROLLED_VALIDITY_REPLAY,
            2,
            1,
            _CONTROL_KINDS,
            1,
            ValidationControlContrast.OBSERVED,
        ),
        (
            ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY,
            3,
            2,
            _CONTROL_KINDS,
            1,
            ValidationControlContrast.OBSERVED,
        ),
    )
    return tuple(
        ValidationDepthRequirement(
            depth=depth,
            depthOrdinal=ordinal,
            requiredClaimTypes=_SUPPORTED_CLAIM_TYPES,
            minimumReplayRepetitions=replay_repetitions,
            requiredControlKinds=control_kinds,
            minimumControlExecutionsPerKind=control_repetitions,
            requiredControlContrast=control_contrast,
        )
        for (
            depth,
            ordinal,
            replay_repetitions,
            control_kinds,
            control_repetitions,
            control_contrast,
        ) in specs
    )
