"""Deployment-owned ABAC for exact Control Plane mutation attributes."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from pajin.control_plane.errors import AuthorizationDenied
from pajin.control_plane.models import ApprovalIntent
from pajin.domain.models import StrictModel, ToolRiskTier
from pajin.runtime.safe_files import parse_strict_json_bytes

_MAX_POLICY_BYTES = 128 * 1024


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class ApprovalDecisionRule(_FrozenStrictModel):
    """Allow one Approver subject to decide one exact signed attribute tuple."""

    principal_subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
    action: Literal["approval.decide"]
    tool_id: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=2_000)
    risk_tier: ToolRiskTier

    @model_validator(mode="after")
    def require_high_risk_attribute(self) -> Self:
        if self.risk_tier < ToolRiskTier.T3:
            raise ValueError("ABAC approval rules may contain only T3 or T4 risk tiers")
        return self

    @property
    def authorization_tuple(self) -> tuple[str, str, str, str, ToolRiskTier]:
        return (
            self.principal_subject,
            self.action,
            self.tool_id,
            self.target,
            self.risk_tier,
        )


class RunSubmissionRule(_FrozenStrictModel):
    """Allow one Operator subject to create one exact submission authority."""

    principal_subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
    action: Literal["run.submit"]
    submission_authority_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def authorization_tuple(self) -> tuple[str, str, str]:
        return (
            self.principal_subject,
            self.action,
            self.submission_authority_digest,
        )


class RunCancellationRule(_FrozenStrictModel):
    """Allow one Operator subject to cancel one exact submission authority."""

    principal_subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
    action: Literal["run.cancel"]
    submission_authority_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def authorization_tuple(self) -> tuple[str, str, str]:
        return (
            self.principal_subject,
            self.action,
            self.submission_authority_digest,
        )


class CheckpointResumeRule(_FrozenStrictModel):
    """Allow one Operator subject to consume one exact continuation authority."""

    principal_subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
    action: Literal["checkpoint.resume"]
    checkpoint_resume_authority_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def authorization_tuple(self) -> tuple[str, str, str]:
        return (
            self.principal_subject,
            self.action,
            self.checkpoint_resume_authority_digest,
        )


class ReplaySourceArtifactAdmissionRule(_FrozenStrictModel):
    """Allow one Operator subject to admit one exact source Artifact handoff."""

    principal_subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
    action: Literal["replay.source-artifact.admit"]
    source_artifact_admission_authority_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def authorization_tuple(self) -> tuple[str, str, str]:
        return (
            self.principal_subject,
            self.action,
            self.source_artifact_admission_authority_digest,
        )


class ReplayBatchAdmissionRule(_FrozenStrictModel):
    """Allow one Operator subject to admit one exact Replay batch request."""

    principal_subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
    action: Literal["replay.batch.admit"]
    replay_batch_admission_authority_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def authorization_tuple(self) -> tuple[str, str, str]:
        return (
            self.principal_subject,
            self.action,
            self.replay_batch_admission_authority_digest,
        )


class MaintenanceRequeueExpiredRule(_FrozenStrictModel):
    """Allow one Operator subject to invoke the explicit expired-state sweep."""

    principal_subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
    action: Literal["maintenance.requeue-expired"]

    @property
    def authorization_tuple(self) -> tuple[str, str]:
        return (self.principal_subject, self.action)


class ControlPlaneABACPolicy(_FrozenStrictModel):
    """Versioned exact allow policy for approval decisions."""

    api_version: Literal["pajin.control-plane.abac-policy/v1"] = (
        "pajin.control-plane.abac-policy/v1"
    )
    policy_id: str = Field(pattern=r"^abac-policy_[0-9a-f]{32}$")
    approval_decision_rules: tuple[ApprovalDecisionRule, ...] = Field(
        min_length=1,
        max_length=1_024,
    )

    @model_validator(mode="after")
    def require_unique_exact_rules(self) -> Self:
        rules = [rule.authorization_tuple for rule in self.approval_decision_rules]
        if len(rules) != len(set(rules)):
            raise ValueError("ABAC approval decision rules must be unique")
        return self

    @property
    def principal_subjects(self) -> frozenset[str]:
        return frozenset(rule.principal_subject for rule in self.approval_decision_rules)


class ControlPlaneRunSubmissionABACPolicy(_FrozenStrictModel):
    """Versioned exact allow policy for Operator Run submission."""

    api_version: Literal["pajin.control-plane.run-submission-abac-policy/v1"] = (
        "pajin.control-plane.run-submission-abac-policy/v1"
    )
    policy_id: str = Field(pattern=r"^run-submit-policy_[0-9a-f]{32}$")
    run_submission_rules: tuple[RunSubmissionRule, ...] = Field(
        min_length=1,
        max_length=1_024,
    )

    @model_validator(mode="after")
    def require_unique_exact_rules(self) -> Self:
        rules = [rule.authorization_tuple for rule in self.run_submission_rules]
        if len(rules) != len(set(rules)):
            raise ValueError("ABAC Run submission rules must be unique")
        return self

    @property
    def principal_subjects(self) -> frozenset[str]:
        return frozenset(rule.principal_subject for rule in self.run_submission_rules)


class ControlPlaneRunCancellationABACPolicy(_FrozenStrictModel):
    """Versioned exact allow policy for Operator Run cancellation."""

    api_version: Literal["pajin.control-plane.run-cancellation-abac-policy/v1"] = (
        "pajin.control-plane.run-cancellation-abac-policy/v1"
    )
    policy_id: str = Field(pattern=r"^run-cancel-policy_[0-9a-f]{32}$")
    run_cancellation_rules: tuple[RunCancellationRule, ...] = Field(
        min_length=1,
        max_length=1_024,
    )

    @model_validator(mode="after")
    def require_unique_exact_rules(self) -> Self:
        rules = [rule.authorization_tuple for rule in self.run_cancellation_rules]
        if len(rules) != len(set(rules)):
            raise ValueError("ABAC Run cancellation rules must be unique")
        return self

    @property
    def principal_subjects(self) -> frozenset[str]:
        return frozenset(rule.principal_subject for rule in self.run_cancellation_rules)


class ControlPlaneCheckpointResumeABACPolicy(_FrozenStrictModel):
    """Versioned exact allow policy for Operator checkpoint resume."""

    api_version: Literal["pajin.control-plane.checkpoint-resume-abac-policy/v1"] = (
        "pajin.control-plane.checkpoint-resume-abac-policy/v1"
    )
    policy_id: str = Field(pattern=r"^checkpoint-resume-policy_[0-9a-f]{32}$")
    checkpoint_resume_rules: tuple[CheckpointResumeRule, ...] = Field(
        min_length=1,
        max_length=1_024,
    )

    @model_validator(mode="after")
    def require_unique_exact_rules(self) -> Self:
        rules = [rule.authorization_tuple for rule in self.checkpoint_resume_rules]
        if len(rules) != len(set(rules)):
            raise ValueError("ABAC checkpoint resume rules must be unique")
        return self

    @property
    def principal_subjects(self) -> frozenset[str]:
        return frozenset(rule.principal_subject for rule in self.checkpoint_resume_rules)


class ControlPlaneReplaySourceArtifactABACPolicy(_FrozenStrictModel):
    """Versioned exact allow policy for managed Replay source admission."""

    api_version: Literal["pajin.control-plane.replay-source-artifact-abac-policy/v1"] = (
        "pajin.control-plane.replay-source-artifact-abac-policy/v1"
    )
    policy_id: str = Field(pattern=r"^replay-source-artifact-policy_[0-9a-f]{32}$")
    replay_source_artifact_admission_rules: tuple[ReplaySourceArtifactAdmissionRule, ...] = Field(
        min_length=1,
        max_length=1_024,
    )

    @model_validator(mode="after")
    def require_unique_exact_rules(self) -> Self:
        rules = [rule.authorization_tuple for rule in self.replay_source_artifact_admission_rules]
        if len(rules) != len(set(rules)):
            raise ValueError("ABAC Replay source Artifact admission rules must be unique")
        return self

    @property
    def principal_subjects(self) -> frozenset[str]:
        return frozenset(
            rule.principal_subject for rule in self.replay_source_artifact_admission_rules
        )


class ControlPlaneReplayBatchAdmissionABACPolicy(_FrozenStrictModel):
    """Versioned exact allow policy for Replay batch admission."""

    api_version: Literal["pajin.control-plane.replay-batch-admission-abac-policy/v1"] = (
        "pajin.control-plane.replay-batch-admission-abac-policy/v1"
    )
    policy_id: str = Field(pattern=r"^replay-batch-admission-policy_[0-9a-f]{32}$")
    replay_batch_admission_rules: tuple[ReplayBatchAdmissionRule, ...] = Field(
        min_length=1,
        max_length=1_024,
    )

    @model_validator(mode="after")
    def require_unique_exact_rules(self) -> Self:
        rules = [rule.authorization_tuple for rule in self.replay_batch_admission_rules]
        if len(rules) != len(set(rules)):
            raise ValueError("ABAC Replay batch admission rules must be unique")
        return self

    @property
    def principal_subjects(self) -> frozenset[str]:
        return frozenset(rule.principal_subject for rule in self.replay_batch_admission_rules)


class ControlPlaneMaintenanceABACPolicy(_FrozenStrictModel):
    """Versioned exact allow policy for explicit Human maintenance actions."""

    api_version: Literal["pajin.control-plane.maintenance-abac-policy/v1"] = (
        "pajin.control-plane.maintenance-abac-policy/v1"
    )
    policy_id: str = Field(pattern=r"^maintenance-policy_[0-9a-f]{32}$")
    maintenance_requeue_expired_rules: tuple[MaintenanceRequeueExpiredRule, ...] = Field(
        min_length=1,
        max_length=1_024,
    )

    @model_validator(mode="after")
    def require_unique_exact_rules(self) -> Self:
        rules = [rule.authorization_tuple for rule in self.maintenance_requeue_expired_rules]
        if len(rules) != len(set(rules)):
            raise ValueError("ABAC maintenance requeue-expired rules must be unique")
        return self

    @property
    def principal_subjects(self) -> frozenset[str]:
        return frozenset(rule.principal_subject for rule in self.maintenance_requeue_expired_rules)


def parse_control_plane_abac_policy(content: bytes) -> ControlPlaneABACPolicy:
    """Parse one bounded strict-JSON approval policy."""

    decoded = parse_strict_json_bytes(
        content,
        label="Control Plane ABAC policy",
        max_bytes=_MAX_POLICY_BYTES,
        max_depth=12,
        max_nodes=4_096,
    )
    return ControlPlaneABACPolicy.model_validate(decoded)


def parse_run_submission_abac_policy(content: bytes) -> ControlPlaneRunSubmissionABACPolicy:
    """Parse one bounded strict-JSON Run submission policy."""

    decoded = parse_strict_json_bytes(
        content,
        label="Control Plane Run submission ABAC policy",
        max_bytes=_MAX_POLICY_BYTES,
        max_depth=12,
        max_nodes=4_096,
    )
    return ControlPlaneRunSubmissionABACPolicy.model_validate(decoded)


def parse_run_cancellation_abac_policy(
    content: bytes,
) -> ControlPlaneRunCancellationABACPolicy:
    """Parse one bounded strict-JSON Run cancellation policy."""

    decoded = parse_strict_json_bytes(
        content,
        label="Control Plane Run cancellation ABAC policy",
        max_bytes=_MAX_POLICY_BYTES,
        max_depth=12,
        max_nodes=4_096,
    )
    return ControlPlaneRunCancellationABACPolicy.model_validate(decoded)


def parse_checkpoint_resume_abac_policy(
    content: bytes,
) -> ControlPlaneCheckpointResumeABACPolicy:
    """Parse one bounded strict-JSON checkpoint resume ABAC policy."""

    decoded = parse_strict_json_bytes(
        content,
        label="Control Plane checkpoint resume ABAC policy",
        max_bytes=_MAX_POLICY_BYTES,
        max_depth=12,
        max_nodes=4_096,
    )
    return ControlPlaneCheckpointResumeABACPolicy.model_validate(decoded)


def parse_replay_source_artifact_abac_policy(
    content: bytes,
) -> ControlPlaneReplaySourceArtifactABACPolicy:
    """Parse one bounded strict-JSON Replay source Artifact admission policy."""

    decoded = parse_strict_json_bytes(
        content,
        label="Control Plane Replay source Artifact ABAC policy",
        max_bytes=_MAX_POLICY_BYTES,
        max_depth=12,
        max_nodes=4_096,
    )
    return ControlPlaneReplaySourceArtifactABACPolicy.model_validate(decoded)


def parse_replay_batch_admission_abac_policy(
    content: bytes,
) -> ControlPlaneReplayBatchAdmissionABACPolicy:
    """Parse one bounded strict-JSON Replay batch admission policy."""

    decoded = parse_strict_json_bytes(
        content,
        label="Control Plane Replay batch admission ABAC policy",
        max_bytes=_MAX_POLICY_BYTES,
        max_depth=12,
        max_nodes=4_096,
    )
    return ControlPlaneReplayBatchAdmissionABACPolicy.model_validate(decoded)


def parse_maintenance_abac_policy(content: bytes) -> ControlPlaneMaintenanceABACPolicy:
    """Parse one bounded strict-JSON explicit maintenance policy."""

    decoded = parse_strict_json_bytes(
        content,
        label="Control Plane maintenance ABAC policy",
        max_bytes=_MAX_POLICY_BYTES,
        max_depth=12,
        max_nodes=4_096,
    )
    return ControlPlaneMaintenanceABACPolicy.model_validate(decoded)


class ControlPlaneABACAuthorizer:
    """Default-deny exact matching over server-verified approval attributes."""

    def __init__(self, policy: ControlPlaneABACPolicy) -> None:
        self._approval_decision_rules = frozenset(
            rule.authorization_tuple for rule in policy.approval_decision_rules
        )

    def authorize_approval_decision(
        self,
        *,
        principal_subject: str,
        intent: ApprovalIntent,
    ) -> None:
        authorization = (
            principal_subject,
            "approval.decide",
            intent.tool_id,
            intent.target,
            intent.risk_tier,
        )
        if authorization not in self._approval_decision_rules:
            raise AuthorizationDenied("ABAC policy denied the approval decision")


class ControlPlaneRunSubmissionAuthorizer:
    """Default-deny exact matching over canonical submission authority."""

    def __init__(self, policy: ControlPlaneRunSubmissionABACPolicy) -> None:
        self._run_submission_rules = frozenset(
            rule.authorization_tuple for rule in policy.run_submission_rules
        )

    def authorize_run_submission(
        self,
        *,
        principal_subject: str,
        submission_authority_digest: str,
    ) -> None:
        authorization = (
            principal_subject,
            "run.submit",
            submission_authority_digest,
        )
        if authorization not in self._run_submission_rules:
            raise AuthorizationDenied("ABAC policy denied the Run submission")


class ControlPlaneRunCancellationAuthorizer:
    """Default-deny exact matching over immutable submission authority."""

    def __init__(self, policy: ControlPlaneRunCancellationABACPolicy) -> None:
        self._run_cancellation_rules = frozenset(
            rule.authorization_tuple for rule in policy.run_cancellation_rules
        )

    def authorize_run_cancellation(
        self,
        *,
        principal_subject: str,
        submission_authority_digest: str | None,
    ) -> None:
        if submission_authority_digest is None:
            raise AuthorizationDenied("ABAC policy denied the Run cancellation")
        authorization = (
            principal_subject,
            "run.cancel",
            submission_authority_digest,
        )
        if authorization not in self._run_cancellation_rules:
            raise AuthorizationDenied("ABAC policy denied the Run cancellation")


class ControlPlaneCheckpointResumeAuthorizer:
    """Default-deny exact matching over verified continuation authority."""

    def __init__(self, policy: ControlPlaneCheckpointResumeABACPolicy) -> None:
        self._checkpoint_resume_rules = frozenset(
            rule.authorization_tuple for rule in policy.checkpoint_resume_rules
        )

    def authorize_checkpoint_resume(
        self,
        *,
        principal_subject: str,
        checkpoint_resume_authority_digest: str,
    ) -> None:
        authorization = (
            principal_subject,
            "checkpoint.resume",
            checkpoint_resume_authority_digest,
        )
        if authorization not in self._checkpoint_resume_rules:
            raise AuthorizationDenied("ABAC policy denied the checkpoint resume")


class ControlPlaneReplaySourceArtifactAuthorizer:
    """Default-deny exact matching over a managed source admission handoff."""

    def __init__(self, policy: ControlPlaneReplaySourceArtifactABACPolicy) -> None:
        self._replay_source_artifact_admission_rules = frozenset(
            rule.authorization_tuple for rule in policy.replay_source_artifact_admission_rules
        )

    def authorize_replay_source_artifact_admission(
        self,
        *,
        principal_subject: str,
        source_artifact_admission_authority_digest: str,
    ) -> None:
        authorization = (
            principal_subject,
            "replay.source-artifact.admit",
            source_artifact_admission_authority_digest,
        )
        if authorization not in self._replay_source_artifact_admission_rules:
            raise AuthorizationDenied("ABAC policy denied the Replay source Artifact admission")


class ControlPlaneReplayBatchAdmissionAuthorizer:
    """Default-deny exact matching over a Replay batch admission request."""

    def __init__(self, policy: ControlPlaneReplayBatchAdmissionABACPolicy) -> None:
        self._replay_batch_admission_rules = frozenset(
            rule.authorization_tuple for rule in policy.replay_batch_admission_rules
        )

    def authorize_replay_batch_admission(
        self,
        *,
        principal_subject: str,
        replay_batch_admission_authority_digest: str,
    ) -> None:
        authorization = (
            principal_subject,
            "replay.batch.admit",
            replay_batch_admission_authority_digest,
        )
        if authorization not in self._replay_batch_admission_rules:
            raise AuthorizationDenied("ABAC policy denied the Replay batch admission")


class ControlPlaneMaintenanceAuthorizer:
    """Default-deny exact matching for explicit Human maintenance actions."""

    def __init__(self, policy: ControlPlaneMaintenanceABACPolicy) -> None:
        self._maintenance_requeue_expired_rules = frozenset(
            rule.authorization_tuple for rule in policy.maintenance_requeue_expired_rules
        )

    def authorize_requeue_expired(self, *, principal_subject: str) -> None:
        authorization = (principal_subject, "maintenance.requeue-expired")
        if authorization not in self._maintenance_requeue_expired_rules:
            raise AuthorizationDenied("ABAC policy denied the maintenance requeue-expired action")
