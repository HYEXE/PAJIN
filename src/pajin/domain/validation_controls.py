"""Information-only validation Control contracts.

These artifacts intentionally have no confirmation or severity authority.  They
bind fresh-capability Baseline, Negative Control, and Counterfactual executions
to one exact validity Claim and preserve their request/evidence lineage.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Literal

from pydantic import Field, model_validator

from pajin.domain.models import StrictModel

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_PORTABLE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"
_DIGEST_PATTERN = r"^[a-f0-9]{64}$"


def validation_control_digest(value: object) -> str:
    """Return the strict canonical JSON digest used by Control artifacts."""

    return sha256(
        json.dumps(
            _json_ready(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _json_ready(value: object) -> object:
    if isinstance(value, datetime):
        return _normalized_utc(value).isoformat().replace("+00:00", "Z")
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_ready(item) for item in value]
    return value


def _normalized_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Control timestamp must include an explicit UTC offset or Z")
    return value.astimezone(UTC)


class ValidationControlKind(StrEnum):
    BASELINE = "baseline"
    NEGATIVE_CONTROL = "negative-control"
    COUNTERFACTUAL = "counterfactual"


class ValidationControlAttemptStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"
    INVALID = "invalid"


class ValidationControlContrast(StrEnum):
    OBSERVED = "contrast-observed"
    NOT_OBSERVED = "contrast-not-observed"
    INCONCLUSIVE = "inconclusive"


class ValidationControlDefinition(StrictModel):
    control_id: str = Field(alias="controlId", pattern=_IDENTIFIER_PATTERN)
    control_kind: ValidationControlKind = Field(alias="controlKind")
    request_id: str = Field(alias="requestId", pattern=_PORTABLE_IDENTIFIER_PATTERN)
    request_digest: str = Field(alias="requestDigest", pattern=_DIGEST_PATTERN)
    session_id: str = Field(alias="sessionId", min_length=3, max_length=128)
    expected_observed: bool = Field(alias="expectedObserved")


class ValidationControlPlan(StrictModel):
    """Trusted plan for the three controls attached to one validity Claim."""

    api_version: Literal["pajin.dev/validation-control-plan/v1alpha1"] = Field(
        default="pajin.dev/validation-control-plan/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ValidationControlPlan"] = "ValidationControlPlan"
    plan_id: str = Field(alias="planId", pattern=_IDENTIFIER_PATTERN)
    source_run_id: str = Field(alias="sourceRunId", pattern=_IDENTIFIER_PATTERN)
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=_DIGEST_PATTERN)
    candidate_id: str = Field(alias="candidateId", pattern=_IDENTIFIER_PATTERN)
    candidate_claim_digest: str = Field(
        alias="candidateClaimDigest",
        pattern=_DIGEST_PATTERN,
    )
    claim_id: str = Field(alias="claimId", pattern=_IDENTIFIER_PATTERN)
    claim_digest: str = Field(alias="claimDigest", pattern=_DIGEST_PATTERN)
    scenario_id: str = Field(alias="scenarioId", pattern=_IDENTIFIER_PATTERN)
    original_request_id: str = Field(
        alias="originalRequestId",
        pattern=_PORTABLE_IDENTIFIER_PATTERN,
    )
    original_request_digest: str = Field(
        alias="originalRequestDigest",
        pattern=_DIGEST_PATTERN,
    )
    executor_id: Literal["trusted-core:kisa-validation-control-executor"] = Field(
        default="trusted-core:kisa-validation-control-executor",
        alias="executorId",
    )
    controls: list[ValidationControlDefinition] = Field(min_length=3, max_length=3)
    informational_only: Literal[True] = Field(default=True, alias="informationalOnly")
    confirmation_eligible: Literal[False] = Field(
        default=False,
        alias="confirmationEligible",
    )

    @model_validator(mode="after")
    def require_exact_control_set_and_identity(self) -> ValidationControlPlan:
        expected = set(ValidationControlKind)
        observed = {control.control_kind for control in self.controls}
        if observed != expected or len(observed) != len(self.controls):
            raise ValueError("Control Plan must contain each Control kind exactly once")
        expected_observations = {
            ValidationControlKind.BASELINE: True,
            ValidationControlKind.NEGATIVE_CONTROL: False,
            ValidationControlKind.COUNTERFACTUAL: False,
        }
        if any(
            item.expected_observed is not expected_observations[item.control_kind]
            for item in self.controls
        ):
            raise ValueError("Control Plan expected observations do not match its Control kinds")
        if len({item.control_id for item in self.controls}) != len(self.controls):
            raise ValueError("Control Plan control IDs must be unique")
        if len({item.request_id for item in self.controls}) != len(self.controls):
            raise ValueError("Control Plan request IDs must be unique")
        if len({item.request_digest for item in self.controls}) != len(self.controls):
            raise ValueError("Control Plan request digests must be unique")
        if len({item.session_id for item in self.controls}) != len(self.controls):
            raise ValueError("Control Plan sessions must be unique")
        expected_plan_id = _control_plan_id(self.model_dump(mode="json", by_alias=True))
        if self.plan_id != expected_plan_id:
            raise ValueError("Control Plan ID does not match its canonical content")
        return self


class ValidationControlAttempt(StrictModel):
    attempt_id: str = Field(alias="attemptId", pattern=_IDENTIFIER_PATTERN)
    plan_id: str = Field(alias="planId", pattern=_IDENTIFIER_PATTERN)
    control_id: str = Field(alias="controlId", pattern=_IDENTIFIER_PATTERN)
    control_kind: ValidationControlKind = Field(alias="controlKind")
    capability_grant_id: str = Field(
        alias="capabilityGrantId",
        pattern=_IDENTIFIER_PATTERN,
    )
    capability_parent_grant_id: str = Field(
        alias="capabilityParentGrantId",
        pattern=_IDENTIFIER_PATTERN,
    )
    request_id: str = Field(alias="requestId", pattern=_PORTABLE_IDENTIFIER_PATTERN)
    request_digest: str = Field(alias="requestDigest", pattern=_DIGEST_PATTERN)
    result_digest: str = Field(alias="resultDigest", pattern=_DIGEST_PATTERN)
    evidence: list[str] = Field(min_length=1, max_length=100)
    status: ValidationControlAttemptStatus
    observed: bool | None = None
    started_at: datetime = Field(alias="startedAt")
    completed_at: datetime = Field(alias="completedAt")

    @model_validator(mode="after")
    def require_attempt_identity(self) -> ValidationControlAttempt:
        self.started_at = _normalized_utc(self.started_at)
        self.completed_at = _normalized_utc(self.completed_at)
        if self.completed_at < self.started_at:
            raise ValueError("Control Attempt cannot complete before it starts")
        if len(self.evidence) != len(set(self.evidence)):
            raise ValueError("Control Attempt evidence references must be unique")
        if (self.status is ValidationControlAttemptStatus.SUCCEEDED) != (
            self.observed is not None
        ):
            raise ValueError("only a successful Control Attempt may carry an observation")
        expected = _attempt_id(self.model_dump(mode="json", by_alias=True))
        if self.attempt_id != expected:
            raise ValueError("Control Attempt ID does not match its canonical content")
        return self


class ValidationControlReceipt(StrictModel):
    """PAJIN-local receipt protected by the enclosing Run integrity seal."""

    api_version: Literal["pajin.dev/validation-control-receipt/v1alpha1"] = Field(
        default="pajin.dev/validation-control-receipt/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ValidationControlReceipt"] = "ValidationControlReceipt"
    receipt_id: str = Field(alias="receiptId", pattern=_IDENTIFIER_PATTERN)
    plan_id: str = Field(alias="planId", pattern=_IDENTIFIER_PATTERN)
    attempt_id: str = Field(alias="attemptId", pattern=_IDENTIFIER_PATTERN)
    control_id: str = Field(alias="controlId", pattern=_IDENTIFIER_PATTERN)
    control_kind: ValidationControlKind = Field(alias="controlKind")
    capability_grant_id: str = Field(
        alias="capabilityGrantId",
        pattern=_IDENTIFIER_PATTERN,
    )
    request_id: str = Field(alias="requestId", pattern=_PORTABLE_IDENTIFIER_PATTERN)
    request_digest: str = Field(alias="requestDigest", pattern=_DIGEST_PATTERN)
    result_digest: str = Field(alias="resultDigest", pattern=_DIGEST_PATTERN)
    evidence: list[str] = Field(min_length=1, max_length=100)
    status: ValidationControlAttemptStatus
    observed: bool | None = None
    executor_id: Literal["trusted-core:kisa-validation-control-executor"] = Field(
        default="trusted-core:kisa-validation-control-executor",
        alias="executorId",
    )
    attestation_scope: Literal["pajin-local-sealed-run"] = Field(
        default="pajin-local-sealed-run",
        alias="attestationScope",
    )
    informational_only: Literal[True] = Field(default=True, alias="informationalOnly")
    confirmation_eligible: Literal[False] = Field(
        default=False,
        alias="confirmationEligible",
    )

    @model_validator(mode="after")
    def require_receipt_identity(self) -> ValidationControlReceipt:
        if len(self.evidence) != len(set(self.evidence)):
            raise ValueError("Control Receipt evidence references must be unique")
        if (self.status is ValidationControlAttemptStatus.SUCCEEDED) != (
            self.observed is not None
        ):
            raise ValueError("only a successful Control Receipt may carry an observation")
        expected = _receipt_id(self.model_dump(mode="json", by_alias=True))
        if self.receipt_id != expected:
            raise ValueError("Control Receipt ID does not match its canonical content")
        return self


class ClaimControlReconciliation(StrictModel):
    """Deterministic, information-only contrast result for one validity Claim."""

    api_version: Literal["pajin.dev/claim-control-reconciliation/v1alpha1"] = Field(
        default="pajin.dev/claim-control-reconciliation/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ClaimControlReconciliation"] = "ClaimControlReconciliation"
    reconciliation_id: str = Field(alias="reconciliationId", pattern=_IDENTIFIER_PATTERN)
    plan_id: str = Field(alias="planId", pattern=_IDENTIFIER_PATTERN)
    candidate_id: str = Field(alias="candidateId", pattern=_IDENTIFIER_PATTERN)
    claim_id: str = Field(alias="claimId", pattern=_IDENTIFIER_PATTERN)
    claim_digest: str = Field(alias="claimDigest", pattern=_DIGEST_PATTERN)
    receipt_ids: list[str] = Field(alias="receiptIds", min_length=3, max_length=3)
    contrast: ValidationControlContrast
    rationale: str = Field(min_length=1, max_length=2_000)
    informational_only: Literal[True] = Field(default=True, alias="informationalOnly")
    confirmation_eligible: Literal[False] = Field(
        default=False,
        alias="confirmationEligible",
    )
    candidate_disposition_unchanged: Literal[True] = Field(
        default=True,
        alias="candidateDispositionUnchanged",
    )

    @model_validator(mode="after")
    def require_reconciliation_identity(self) -> ClaimControlReconciliation:
        if len(self.receipt_ids) != len(set(self.receipt_ids)):
            raise ValueError("Control Reconciliation receipt IDs must be unique")
        expected = _reconciliation_id(self.model_dump(mode="json", by_alias=True))
        if self.reconciliation_id != expected:
            raise ValueError("Control Reconciliation ID does not match canonical content")
        return self


def build_validation_control_plan(
    *,
    source_run_id: str,
    source_root_digest: str,
    candidate_id: str,
    candidate_claim_digest: str,
    claim_id: str,
    claim_digest: str,
    scenario_id: str,
    original_request_id: str,
    original_request_digest: str,
    controls: list[ValidationControlDefinition],
) -> ValidationControlPlan:
    payload = {
        "sourceRunId": source_run_id,
        "sourceRootDigest": source_root_digest,
        "candidateId": candidate_id,
        "candidateClaimDigest": candidate_claim_digest,
        "claimId": claim_id,
        "claimDigest": claim_digest,
        "scenarioId": scenario_id,
        "originalRequestId": original_request_id,
        "originalRequestDigest": original_request_digest,
        "executorId": "trusted-core:kisa-validation-control-executor",
        "controls": [item.model_dump(mode="json", by_alias=True) for item in controls],
        "informationalOnly": True,
        "confirmationEligible": False,
    }
    return ValidationControlPlan.model_validate(
        {
            **payload,
            "planId": _control_plan_id(payload),
        }
    )


def build_validation_control_attempt(
    **values: object,
) -> ValidationControlAttempt:
    payload = dict(values)
    payload["attemptId"] = _attempt_id(payload)
    return ValidationControlAttempt.model_validate(payload)


def build_validation_control_receipt(
    attempt: ValidationControlAttempt,
) -> ValidationControlReceipt:
    payload: dict[str, object] = {
        "planId": attempt.plan_id,
        "attemptId": attempt.attempt_id,
        "controlId": attempt.control_id,
        "controlKind": attempt.control_kind,
        "capabilityGrantId": attempt.capability_grant_id,
        "requestId": attempt.request_id,
        "requestDigest": attempt.request_digest,
        "resultDigest": attempt.result_digest,
        "evidence": attempt.evidence,
        "status": attempt.status,
        "observed": attempt.observed,
        "executorId": "trusted-core:kisa-validation-control-executor",
        "attestationScope": "pajin-local-sealed-run",
        "informationalOnly": True,
        "confirmationEligible": False,
    }
    return ValidationControlReceipt.model_validate(
        {
            **payload,
            "receiptId": _receipt_id(payload),
        }
    )


def reconcile_claim_controls(
    plan: ValidationControlPlan,
    receipts: list[ValidationControlReceipt],
) -> ClaimControlReconciliation:
    if len(receipts) != 3:
        raise ValueError("Control Reconciliation requires exactly three receipts")
    by_kind = {item.control_kind: item for item in receipts}
    if set(by_kind) != set(ValidationControlKind) or len(by_kind) != len(receipts):
        raise ValueError("Control Reconciliation requires one receipt per Control kind")
    definitions = {item.control_kind: item for item in plan.controls}
    if any(
        receipt.plan_id != plan.plan_id
        or receipt.control_id != definitions[kind].control_id
        or receipt.request_id != definitions[kind].request_id
        or receipt.request_digest != definitions[kind].request_digest
        for kind, receipt in by_kind.items()
    ):
        raise ValueError("Control Receipt lineage differs from its Plan")
    if len({item.capability_grant_id for item in receipts}) != len(receipts):
        raise ValueError("each Control Receipt requires a fresh Capability")
    evidence_sets = [set(item.evidence) for item in receipts]
    if any(
        left & right
        for index, left in enumerate(evidence_sets)
        for right in evidence_sets[index + 1 :]
    ):
        raise ValueError("Control Receipt evidence lineage must be disjoint")

    if any(
        receipt.status is not ValidationControlAttemptStatus.SUCCEEDED
        for receipt in receipts
    ):
        contrast = ValidationControlContrast.INCONCLUSIVE
        rationale = "At least one fresh Control did not produce a valid trusted observation."
    elif all(
        by_kind[kind].observed is definitions[kind].expected_observed
        for kind in ValidationControlKind
    ):
        contrast = ValidationControlContrast.OBSERVED
        rationale = (
            "The fresh Baseline observation and both expected-negative Controls formed "
            "the planned contrast."
        )
    else:
        contrast = ValidationControlContrast.NOT_OBSERVED
        rationale = (
            "All fresh Controls completed, but their observations did not form the "
            "planned Baseline/negative/counterfactual contrast."
        )

    payload = {
        "planId": plan.plan_id,
        "candidateId": plan.candidate_id,
        "claimId": plan.claim_id,
        "claimDigest": plan.claim_digest,
        "receiptIds": [by_kind[kind].receipt_id for kind in ValidationControlKind],
        "contrast": contrast,
        "rationale": rationale,
        "informationalOnly": True,
        "confirmationEligible": False,
        "candidateDispositionUnchanged": True,
    }
    return ClaimControlReconciliation.model_validate(
        {
            **payload,
            "reconciliationId": _reconciliation_id(payload),
        }
    )


def _control_plan_id(payload: dict[str, object]) -> str:
    canonical = {
        key: value
        for key, value in payload.items()
        if key not in {"planId", "kind", "apiVersion"}
    }
    return f"control-plan_{validation_control_digest(canonical)[:24]}"


def _attempt_id(payload: dict[str, object]) -> str:
    canonical = {key: value for key, value in payload.items() if key != "attemptId"}
    return f"control-attempt_{validation_control_digest(canonical)[:24]}"


def _receipt_id(payload: dict[str, object]) -> str:
    canonical = {
        key: value
        for key, value in payload.items()
        if key not in {"receiptId", "kind", "apiVersion"}
    }
    return f"control-receipt_{validation_control_digest(canonical)[:24]}"


def _reconciliation_id(payload: dict[str, object]) -> str:
    canonical = {
        key: value
        for key, value in payload.items()
        if key not in {"reconciliationId", "kind", "apiVersion"}
    }
    return f"control-reconciliation_{validation_control_digest(canonical)[:24]}"
