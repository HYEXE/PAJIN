"""Strict source-integrity loading for sealed WEB-003 assessment Runs.

This module verifies that one already-produced WEB-003 Run is internally intact and
matches an independently supplied Run identity.  It deliberately does not execute the
target, independently replay a diagnostic, or confer PAJIN Finding authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator

from pajin.domain.models import StrictModel
from pajin.runtime.pinned_workspace import pinned_workspace_relative_path
from pajin.runtime.store import (
    RunIntegrityVerification,
    SealedArtifact,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json
from pajin.web_assessment.discovery_evidence import AuthenticatedDiscoveryEvidence
from pajin.web_assessment.models import (
    LocalWebAssessmentAuthorization,
    LocalWebAssessmentResult,
    RequestEvidence,
    WebAssessmentPlan,
    request_evidence_sequence,
)
from pajin.web_assessment.report import render_local_web_assessment_report

_RUN_ID_PATTERN = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_SCREENSHOT_PATH_PATTERN = re.compile(r"^evidence/[a-z0-9][a-z0-9._-]{0,199}\.png$")

_PLAN_PATH = "plan.json"
_AUTHORIZATION_PATH = "authorization.json"
_RESULT_PATH = "result.json"
_REPORT_PATH = "report.md"
_PROVISIONING_RECEIPT_PATH = "provisioning-receipt.json"
_DISCOVERY_EVIDENCE_PATH = "discovery-evidence.json"
_CORE_PATHS = frozenset({_PLAN_PATH, _AUTHORIZATION_PATH, _RESULT_PATH, _REPORT_PATH})
_OPTIONAL_PATHS = frozenset({_PROVISIONING_RECEIPT_PATH, _DISCOVERY_EVIDENCE_PATH})

_MAX_PLAN_BYTES = 1 * 1024 * 1024
_MAX_AUTHORIZATION_BYTES = 256 * 1024
_MAX_RESULT_BYTES = 16 * 1024 * 1024
_MAX_REPORT_BYTES = 16 * 1024 * 1024
_MAX_PROVISIONING_RECEIPT_BYTES = 1 * 1024 * 1024
_MAX_DISCOVERY_EVIDENCE_BYTES = 8 * 1024 * 1024
_MAX_SCREENSHOT_BYTES = 10_000_000


class LocalWebAssessmentSourceIntegrityError(ValueError):
    """Raised when sealed WEB-003 source evidence fails closed."""


class _ProvisioningReceipt(StrictModel):
    """Strict interpretation of the optional secret-free provisioning receipt."""

    api_version: Literal["pajin.dev/local-web-assessment-provisioning/v1alpha1"] = Field(
        alias="apiVersion"
    )
    kind: Literal["LocalWebAssessmentProvisioningReceipt"]
    plan_digest: str = Field(alias="planDigest", pattern=r"^[a-f0-9]{64}$")
    authorization_id: str = Field(alias="authorizationId", min_length=1, max_length=110)
    origin: str
    target_product: str = Field(alias="targetProduct", min_length=1, max_length=100)
    target_version: str = Field(alias="targetVersion", min_length=1, max_length=100)
    provisioned_at: datetime = Field(alias="provisionedAt")
    requests: tuple[RequestEvidence, ...] = Field(max_length=20)
    account_retained_in_local_lab: Literal[True] = Field(alias="accountRetainedInLocalLab")
    credentials_persisted: Literal[False] = Field(alias="credentialsPersisted")

    @field_validator("provisioned_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("provisioning receipt time requires an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator("target_product")
    @classmethod
    def require_canonical_target_product(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("provisioning receipt target product must be canonical")
        return value


@dataclass(frozen=True, slots=True)
class VerifiedLocalWebAssessmentSourceIntegrity:
    """One exact WEB-003 source Run, without replay or Finding authority semantics."""

    run_path: Path
    verification: RunIntegrityVerification
    plan: WebAssessmentPlan
    authorization: LocalWebAssessmentAuthorization
    result: LocalWebAssessmentResult
    report_markdown: str
    screenshot_references: tuple[str, ...]
    semantics: Literal["source-integrity-only"] = "source-integrity-only"
    independent_replay_verified: Literal[False] = False
    finding_authority: Literal[False] = False
    discovery_evidence: AuthenticatedDiscoveryEvidence | None = None


def _artifact_records(snapshot: VerifiedRunSnapshot) -> dict[str, SealedArtifact]:
    records = {artifact.path: artifact for seal in snapshot.seals for artifact in seal.artifacts}
    expected_count = sum(len(seal.artifacts) for seal in snapshot.seals)
    if len(records) != expected_count:
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source seal contains duplicate artifact paths"
        )
    return records


def _require_run_shape(
    snapshot: VerifiedRunSnapshot,
    *,
    expected_root_digest: str,
) -> dict[str, SealedArtifact]:
    verification = snapshot.verification
    if verification.root_digest != expected_root_digest:
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source root digest differs from the expected Run"
        )
    if verification.seal_count != 1 or len(snapshot.seals) != 1:
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source requires exactly one final integrity seal"
        )
    if verification.event_count != 2 or len(snapshot.events) != 2:
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source requires exactly two sealed audit events"
        )
    if tuple(event.event_type for event in snapshot.events) != (
        "web-assessment.started",
        "web-assessment.completed",
    ):
        raise LocalWebAssessmentSourceIntegrityError("WEB-003 source audit event inventory differs")

    records = _artifact_records(snapshot)
    if verification.artifact_count != len(records):
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source artifact inventory differs from its verification"
        )
    screenshot_records = {
        path: record
        for path, record in records.items()
        if _SCREENSHOT_PATH_PATTERN.fullmatch(path) is not None
    }
    unexpected = set(records) - _CORE_PATHS - _OPTIONAL_PATHS - set(screenshot_records)
    if unexpected:
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source contains an unsupported sealed artifact"
        )
    if not _CORE_PATHS.issubset(records):
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source is missing a required sealed artifact"
        )
    if not 2 <= len(screenshot_records) <= 32:
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source screenshot artifact inventory is out of bounds"
        )
    _require_record_limits(records)
    return records


def _require_record_limits(records: Mapping[str, SealedArtifact]) -> None:
    limits = {
        _PLAN_PATH: _MAX_PLAN_BYTES,
        _AUTHORIZATION_PATH: _MAX_AUTHORIZATION_BYTES,
        _RESULT_PATH: _MAX_RESULT_BYTES,
        _REPORT_PATH: _MAX_REPORT_BYTES,
        _PROVISIONING_RECEIPT_PATH: _MAX_PROVISIONING_RECEIPT_BYTES,
        _DISCOVERY_EVIDENCE_PATH: _MAX_DISCOVERY_EVIDENCE_BYTES,
    }
    expected_media_types = {
        _PLAN_PATH: "application/json",
        _AUTHORIZATION_PATH: "application/json",
        _RESULT_PATH: "application/json",
        _REPORT_PATH: "text/markdown",
        _PROVISIONING_RECEIPT_PATH: "application/json",
        _DISCOVERY_EVIDENCE_PATH: "application/json",
    }
    for path, record in records.items():
        if _SCREENSHOT_PATH_PATTERN.fullmatch(path) is not None:
            limit = _MAX_SCREENSHOT_BYTES
            expected_media_type = "application/octet-stream"
        else:
            limit = limits[path]
            expected_media_type = expected_media_types[path]
        if record.size_bytes < 1 or record.size_bytes > limit:
            raise LocalWebAssessmentSourceIntegrityError(
                f"WEB-003 source artifact size is out of bounds: {path}"
            )
        if record.media_type != expected_media_type:
            raise LocalWebAssessmentSourceIntegrityError(
                f"WEB-003 source artifact media type differs: {path}"
            )


def _load_metadata(
    initial: VerifiedRunSnapshot,
    records: Mapping[str, SealedArtifact],
) -> VerifiedRunSnapshot:
    limits = {
        _PLAN_PATH: _MAX_PLAN_BYTES,
        _AUTHORIZATION_PATH: _MAX_AUTHORIZATION_BYTES,
        _RESULT_PATH: _MAX_RESULT_BYTES,
        _REPORT_PATH: _MAX_REPORT_BYTES,
    }
    if _PROVISIONING_RECEIPT_PATH in records:
        limits[_PROVISIONING_RECEIPT_PATH] = _MAX_PROVISIONING_RECEIPT_BYTES
    if _DISCOVERY_EVIDENCE_PATH in records:
        limits[_DISCOVERY_EVIDENCE_PATH] = _MAX_DISCOVERY_EVIDENCE_BYTES
    snapshot = load_verified_run_artifacts(
        initial.run_path,
        requests=limits,
        expected_run_id=initial.verification.run_id,
    )
    require_same_authority(
        initial,
        snapshot,
        message="sealed WEB-003 source changed while metadata was loaded",
    )
    return snapshot


def _strict_model[T: StrictModel](
    snapshot: VerifiedRunSnapshot,
    path: str,
    *,
    label: str,
    max_bytes: int,
    model: type[T],
) -> T:
    try:
        value = strict_json(
            snapshot,
            path,
            label=label,
            max_bytes=max_bytes,
            expected_type=dict,
            missing_or_invalid_message=f"{label} is missing or invalid",
            type_message=f"{label} must contain a JSON object",
        )
        return model.model_validate(value)
    except ValueError as exc:
        raise LocalWebAssessmentSourceIntegrityError(f"{label} failed strict validation") from exc


def _require_model_bindings(
    *,
    snapshot: VerifiedRunSnapshot,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    result: LocalWebAssessmentResult,
) -> None:
    try:
        authorization.require_current(plan=plan, now=result.started_at)
    except ValueError as exc:
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source authorization differs from its plan or execution time"
        ) from exc
    if (
        result.run_id != snapshot.verification.run_id
        or result.plan_name != plan.name
        or result.plan_digest != plan.plan_digest
        or result.authorization_id != authorization.authorization_id
        or result.origin != plan.origin
        or result.origin != authorization.origin
        or result.target_product != plan.target_product
        or result.finished_at > authorization.expires_at
    ):
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source plan, authorization, result, or Run binding differs"
        )
    if any(
        page.captured_at < result.started_at or page.captured_at > result.finished_at
        for page in result.browser.pages
    ):
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source browser evidence falls outside the result time window"
        )

    started, completed = snapshot.events
    if (
        started.occurred_at != result.started_at
        or started.payload
        != {
            "authorizationId": authorization.authorization_id,
            "origin": plan.origin,
            "planDigest": plan.plan_digest,
        }
        or completed.occurred_at != result.finished_at
        or completed.payload
        != {
            "attackPathCount": len(result.attack_paths),
            "issueCount": len(result.issues),
            "resultDigest": result.result_digest,
        }
    ):
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source audit events differ from the strict result"
        )


def _require_provisioning_binding(
    snapshot: VerifiedRunSnapshot,
    *,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    result: LocalWebAssessmentResult,
) -> None:
    if _PROVISIONING_RECEIPT_PATH not in snapshot.artifacts:
        return
    receipt = _strict_model(
        snapshot,
        _PROVISIONING_RECEIPT_PATH,
        label="WEB-003 provisioning receipt",
        max_bytes=_MAX_PROVISIONING_RECEIPT_BYTES,
        model=_ProvisioningReceipt,
    )
    if (
        receipt.plan_digest != plan.plan_digest
        or receipt.authorization_id != authorization.authorization_id
        or receipt.origin != plan.origin
        or receipt.target_product != plan.target_product
        or receipt.target_product != result.target_product
        or receipt.target_version != result.target_version
        or not authorization.approved_at <= receipt.provisioned_at <= result.started_at
        or receipt.provisioned_at >= authorization.expires_at
    ):
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 provisioning receipt differs from its plan, authorization, or result"
        )
    evidence_ids = [request.evidence_id for request in receipt.requests]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 provisioning receipt contains duplicate Evidence IDs"
        )


def _require_discovery_binding(
    snapshot: VerifiedRunSnapshot,
    *,
    plan: WebAssessmentPlan,
    result: LocalWebAssessmentResult,
) -> AuthenticatedDiscoveryEvidence | None:
    artifact_present = _DISCOVERY_EVIDENCE_PATH in snapshot.artifacts
    result_reference_present = result.discovery_evidence_reference is not None
    if artifact_present != result_reference_present:
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 discovery Evidence inventory differs from its result"
        )
    if not artifact_present:
        return None
    evidence = _strict_model(
        snapshot,
        _DISCOVERY_EVIDENCE_PATH,
        label="WEB-003 discovery Evidence",
        max_bytes=_MAX_DISCOVERY_EVIDENCE_BYTES,
        model=AuthenticatedDiscoveryEvidence,
    )
    passive_requests = tuple(
        sorted(
            (
                request
                for request in result.requests
                if request.phase == "browser-passive-discovery"
            ),
            key=request_evidence_sequence,
        )
    )
    if (
        result.discovery_evidence_reference != _DISCOVERY_EVIDENCE_PATH
        or result.discovery_evidence_digest != evidence.evidence_digest
        or evidence.discovery_plan.origin != plan.origin
        or evidence.discovery_result.origin != plan.origin
        or evidence.request_evidence != passive_requests
    ):
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 discovery Evidence differs from its plan or result"
        )
    return evidence


def _load_and_verify_screenshots(
    initial: VerifiedRunSnapshot,
    records: Mapping[str, SealedArtifact],
    result: LocalWebAssessmentResult,
) -> tuple[str, ...]:
    references = tuple(page.screenshot_reference for page in result.browser.pages)
    if len(references) != len(set(references)):
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source result contains duplicate screenshot references"
        )
    if any(_SCREENSHOT_PATH_PATTERN.fullmatch(path) is None for path in references):
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source result contains an invalid screenshot reference"
        )
    expected_paths = _CORE_PATHS | set(references)
    if _PROVISIONING_RECEIPT_PATH in records:
        expected_paths = expected_paths | {_PROVISIONING_RECEIPT_PATH}
    if _DISCOVERY_EVIDENCE_PATH in records:
        expected_paths = expected_paths | {_DISCOVERY_EVIDENCE_PATH}
    if set(records) != expected_paths:
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source screenshot paths differ from the sealed artifact inventory"
        )

    snapshot = load_verified_run_artifacts(
        initial.run_path,
        requests={path: _MAX_SCREENSHOT_BYTES for path in references},
        expected_run_id=initial.verification.run_id,
    )
    require_same_authority(
        initial,
        snapshot,
        message="sealed WEB-003 source changed while screenshots were loaded",
    )
    for page in result.browser.pages:
        content = snapshot.artifact_bytes(page.screenshot_reference)
        record = records[page.screenshot_reference]
        digest = sha256(content).hexdigest()
        if (
            len(content) != page.screenshot_bytes
            or digest != page.screenshot_sha256
            or record.size_bytes != page.screenshot_bytes
            or record.sha256 != page.screenshot_sha256
        ):
            raise LocalWebAssessmentSourceIntegrityError(
                "WEB-003 source screenshot bytes differ from the strict result"
            )
    return references


def load_verified_local_web_assessment_source_integrity(
    run_path: Path,
    *,
    expected_run_id: str,
    expected_root_digest: str,
) -> VerifiedLocalWebAssessmentSourceIntegrity:
    """Load one pinned WEB-003 source Run without claiming independent validation.

    A successful return proves only source integrity and the internal WEB-003 bindings
    checked here.  It is not evidence that another account, ActionPermit, execution, or
    independent replay reproduced any issue, and it cannot authorize a PAJIN Finding.
    """

    if _RUN_ID_PATTERN.fullmatch(expected_run_id) is None:
        raise LocalWebAssessmentSourceIntegrityError("expected WEB-003 source Run ID is invalid")
    if _SHA256_PATTERN.fullmatch(expected_root_digest) is None:
        raise LocalWebAssessmentSourceIntegrityError(
            "expected WEB-003 source root digest must be 64 lowercase hex characters"
        )
    pinned_run_path = pinned_workspace_relative_path(
        run_path,
        label="WEB-003 source Run path",
    )
    initial = load_verified_run_snapshot(
        pinned_run_path if pinned_run_path is not None else run_path.resolve(),
        expected_run_id=expected_run_id,
    )
    records = _require_run_shape(
        initial,
        expected_root_digest=expected_root_digest,
    )
    metadata = _load_metadata(initial, records)
    plan = _strict_model(
        metadata,
        _PLAN_PATH,
        label="WEB-003 plan",
        max_bytes=_MAX_PLAN_BYTES,
        model=WebAssessmentPlan,
    )
    authorization = _strict_model(
        metadata,
        _AUTHORIZATION_PATH,
        label="WEB-003 authorization",
        max_bytes=_MAX_AUTHORIZATION_BYTES,
        model=LocalWebAssessmentAuthorization,
    )
    result = _strict_model(
        metadata,
        _RESULT_PATH,
        label="WEB-003 result",
        max_bytes=_MAX_RESULT_BYTES,
        model=LocalWebAssessmentResult,
    )
    _require_model_bindings(
        snapshot=metadata,
        plan=plan,
        authorization=authorization,
        result=result,
    )
    _require_provisioning_binding(
        metadata,
        plan=plan,
        authorization=authorization,
        result=result,
    )
    discovery_evidence = _require_discovery_binding(
        metadata,
        plan=plan,
        result=result,
    )

    report_bytes = metadata.artifact_bytes(_REPORT_PATH)
    expected_report = render_local_web_assessment_report(
        result,
        discovery_evidence=discovery_evidence,
    ).encode("utf-8")
    if report_bytes != expected_report:
        raise LocalWebAssessmentSourceIntegrityError(
            "WEB-003 source report differs from the exact strict-result rendering"
        )
    screenshots = _load_and_verify_screenshots(initial, records, result)
    current = load_verified_run_snapshot(
        initial.run_path,
        expected_run_id=expected_run_id,
    )
    require_same_authority(
        initial,
        current,
        message="sealed WEB-003 source changed during source-integrity verification",
    )
    return VerifiedLocalWebAssessmentSourceIntegrity(
        run_path=initial.run_path,
        verification=initial.verification.model_copy(deep=True),
        plan=plan,
        authorization=authorization,
        result=result,
        report_markdown=expected_report.decode("utf-8"),
        screenshot_references=screenshots,
        discovery_evidence=discovery_evidence,
    )
