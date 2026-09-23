"""Inert WEB-008 topology for one strictly verified WEB-007 advisory.

This artifact records the closed, code-owned diagnostic order and two future
execution slots.  It does not alter the existing governed Campaign parent or
authorize a Gateway, Permit, target request, Finding, or report.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.agentic.codex_recon_compilation import (
    CodexReconCompilationResult,
    verify_codex_recon_compilation,
)
from pajin.agentic.codex_usage import CodexAdvisoryUsageJournal
from pajin.discovery.canonicalization import discovery_digest
from pajin.web_assessment.diagnostic_catalog import production_diagnostic_bundle_catalog
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun
from pajin.web_assessment.governed_adapter_profile import (
    GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
    production_governed_web_adapter_profile_registry,
)

GOVERNED_WEB_ADVISORY_TOPOLOGY_API_VERSION: Final = (
    "pajin.dev/governed-web-advisory-topology/v1alpha2"
)
_PLAN_DOMAIN: Final = "pajin.governed-web-advisory-plan/v1alpha2"
_SLOT_DOMAIN: Final = "pajin.governed-web-advisory-slot/v1alpha2"
_TOPOLOGY_DOMAIN: Final = "pajin.governed-web-advisory-topology/v1alpha2"
_DIAGNOSTIC_ORDER: Final = ("sql-login", "object-access", "dom-xss")
_PATH_ORDER: Final = (("sql-login", "object-access"), ("dom-xss",))

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class GovernedWebAdvisoryTopologyError(ValueError):
    """A proposed topology differs from current sealed or installed authority."""


class _WireModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )


class GovernedWebAdvisoryStageSlot(_WireModel):
    """Distinct future role slot with no claim, dispatch, or action authority."""

    role: Literal["source", "validation"]
    stage: Literal["source-gateway", "validation-gateway"]
    plan_digest: _Sha256 = Field(alias="planDigest")
    slot_digest: _Sha256 = Field(alias="slotDigest")
    state: Literal["planned-no-dispatch"]
    approval_recorded: Literal[False] = Field(alias="approvalRecorded")
    permit_granted: Literal[False] = Field(alias="permitGranted")
    gateway_dispatched: Literal[False] = Field(alias="gatewayDispatched")

    @field_validator("approval_recorded", "permit_granted", "gateway_dispatched", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> Literal[False]:
        if type(value) is not bool or value is not False:
            raise ValueError("advisory slot authority must be literal false")
        return False

    @model_validator(mode="after")
    def bind_slot(self) -> Self:
        if self.stage != f"{self.role}-gateway":
            raise ValueError("advisory stage role and stage differ")
        expected = discovery_digest(
            _SLOT_DOMAIN,
            {"role": self.role, "stage": self.stage, "planDigest": self.plan_digest},
        )
        if self.slot_digest != expected:
            raise ValueError("advisory stage slot digest differs")
        return self


class GovernedWebAdvisoryTopology(_WireModel):
    """Content-addressed, read-only candidate for a future governed Campaign."""

    api_version: Literal["pajin.dev/governed-web-advisory-topology/v1alpha2"] = Field(
        alias="apiVersion"
    )
    kind: Literal["GovernedWebAdvisoryTopology"]
    topology_digest: _Sha256 = Field(alias="topologyDigest")
    plan_digest: _Sha256 = Field(alias="planDigest")
    source_run_id: str = Field(alias="sourceRunId", pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_snapshot_digest: _Sha256 = Field(alias="sourceSnapshotDigest")
    bridge_digest: _Sha256 = Field(alias="bridgeDigest")
    receipt_digest: _Sha256 = Field(alias="receiptDigest")
    compiled_proposal_digest: _Sha256 = Field(alias="compiledProposalDigest")
    profile_digest: _Sha256 = Field(alias="profileDigest")
    diagnostic_catalog_digest: _Sha256 = Field(alias="diagnosticCatalogDigest")
    diagnostic_bundle_digest: _Sha256 = Field(alias="diagnosticBundleDigest")
    diagnostic_order: tuple[Literal["sql-login"], Literal["object-access"], Literal["dom-xss"]] = (
        Field(alias="diagnosticOrder")
    )
    attack_path_order: tuple[
        tuple[Literal["sql-login"], Literal["object-access"]],
        tuple[Literal["dom-xss"]],
    ] = Field(alias="attackPathOrder")
    stage_slots: tuple[GovernedWebAdvisoryStageSlot, GovernedWebAdvisoryStageSlot] = Field(
        alias="stageSlots"
    )
    state: Literal["candidate-topology-not-authorized"]
    diagnostic_rank_is_execution_order: Literal[False] = Field(
        alias="diagnosticRankIsExecutionOrder"
    )
    scope_expansion_authorized: Literal[False] = Field(alias="scopeExpansionAuthorized")
    model_call_authorized: Literal[False] = Field(alias="modelCallAuthorized")
    target_request_authorized: Literal[False] = Field(alias="targetRequestAuthorized")
    capability_granted: Literal[False] = Field(alias="capabilityGranted")
    approval_recorded: Literal[False] = Field(alias="approvalRecorded")
    permit_granted: Literal[False] = Field(alias="permitGranted")
    execution_authorized: Literal[False] = Field(alias="executionAuthorized")
    finding_authorized: Literal[False] = Field(alias="findingAuthorized")
    graph_admission_authorized: Literal[False] = Field(alias="graphAdmissionAuthorized")
    report_authorized: Literal[False] = Field(alias="reportAuthorized")

    @field_validator(
        "diagnostic_rank_is_execution_order",
        "scope_expansion_authorized",
        "model_call_authorized",
        "target_request_authorized",
        "capability_granted",
        "approval_recorded",
        "permit_granted",
        "execution_authorized",
        "finding_authorized",
        "graph_admission_authorized",
        "report_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> Literal[False]:
        if type(value) is not bool or value is not False:
            raise ValueError("advisory topology authority must be literal false")
        return False

    @model_validator(mode="after")
    def bind_topology(self) -> Self:
        if self.diagnostic_order != _DIAGNOSTIC_ORDER or self.attack_path_order != _PATH_ORDER:
            raise ValueError("advisory topology differs from the fixed code-owned order")
        if tuple(slot.role for slot in self.stage_slots) != ("source", "validation"):
            raise ValueError("advisory topology requires distinct source and validation slots")
        if any(slot.plan_digest != self.plan_digest for slot in self.stage_slots):
            raise ValueError("advisory stage slot names a different plan")
        if self.plan_digest != _plan_digest(
            source_run_id=self.source_run_id,
            source_root_digest=self.source_root_digest,
            source_snapshot_digest=self.source_snapshot_digest,
            bridge_digest=self.bridge_digest,
            receipt_digest=self.receipt_digest,
            compiled_proposal_digest=self.compiled_proposal_digest,
            profile_digest=self.profile_digest,
            diagnostic_catalog_digest=self.diagnostic_catalog_digest,
            diagnostic_bundle_digest=self.diagnostic_bundle_digest,
        ):
            raise ValueError("advisory plan digest differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"topology_digest"})
        if self.topology_digest != discovery_digest(_TOPOLOGY_DOMAIN, material):
            raise ValueError("advisory topology digest differs")
        return self


def _plan_digest(
    *,
    source_run_id: str,
    source_root_digest: str,
    source_snapshot_digest: str,
    bridge_digest: str,
    receipt_digest: str,
    compiled_proposal_digest: str,
    profile_digest: str,
    diagnostic_catalog_digest: str,
    diagnostic_bundle_digest: str,
) -> str:
    return discovery_digest(
        _PLAN_DOMAIN,
        {
            "sourceRunId": source_run_id,
            "sourceRootDigest": source_root_digest,
            "sourceSnapshotDigest": source_snapshot_digest,
            "bridgeDigest": bridge_digest,
            "receiptDigest": receipt_digest,
            "compiledProposalDigest": compiled_proposal_digest,
            "profileDigest": profile_digest,
            "diagnosticCatalogDigest": diagnostic_catalog_digest,
            "diagnosticBundleDigest": diagnostic_bundle_digest,
            "diagnosticOrder": _DIAGNOSTIC_ORDER,
            "attackPathOrder": _PATH_ORDER,
        },
    )


def _slot(role: Literal["source", "validation"], plan_digest: str) -> dict[str, object]:
    stage = f"{role}-gateway"
    return {
        "role": role,
        "stage": stage,
        "planDigest": plan_digest,
        "slotDigest": discovery_digest(
            _SLOT_DOMAIN, {"role": role, "stage": stage, "planDigest": plan_digest}
        ),
        "state": "planned-no-dispatch",
        "approvalRecorded": False,
        "permitGranted": False,
        "gatewayDispatched": False,
    }


def build_governed_web_advisory_topology(
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    compilation: CodexReconCompilationResult,
    journal: CodexAdvisoryUsageJournal,
    attempt_id: str,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    expected_receipt_digest: str,
    expected_proposal_digest: str,
    expected_profile_digest: str,
    expected_diagnostic_catalog_digest: str,
    expected_diagnostic_bundle_digest: str,
) -> GovernedWebAdvisoryTopology:
    """Reverify exact inputs before recording a non-executable topology."""

    try:
        if (
            type(source) is not VerifiedAuthenticatedDiscoveryRun
            or type(compilation) is not CodexReconCompilationResult
            or type(journal) is not CodexAdvisoryUsageJournal
            or source.verification.run_id != expected_source_run_id
            or source.verification.root_digest != expected_source_root_digest
        ):
            raise ValueError("advisory topology inputs differ from independent pins")
        current = verify_codex_recon_compilation(
            compilation,
            source,
            expected_source_run_id=expected_source_run_id,
            expected_source_root_digest=expected_source_root_digest,
            journal=journal,
            attempt_id=attempt_id,
            expected_receipt_digest=expected_receipt_digest,
        )
        record = current.record
        verified = current.proposal
        current_snapshot = current.snapshot
        if (
            record.receipt_digest != expected_receipt_digest
            or record.compiled_proposal_digest != expected_proposal_digest
            or verified.proposal_digest != expected_proposal_digest
        ):
            raise ValueError("advisory topology bridge differs from independently pinned receipt")
        profile = production_governed_web_adapter_profile_registry().resolve(
            adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
            origin=source.plan.origin,
        )
        catalog = production_diagnostic_bundle_catalog()
        descriptor = catalog.resolve(
            adapter_implementation_id=profile.implementation_id,
            adapter_implementation_digest=profile.implementation_digest,
        )
        if (
            profile.plan != source.plan
            or profile.profile_digest != expected_profile_digest
            or descriptor.catalog_digest != expected_diagnostic_catalog_digest
            or descriptor.bundle_digest != expected_diagnostic_bundle_digest
            or current_snapshot.profile_digest != profile.profile_digest
            or current_snapshot.diagnostic_catalog_digest != descriptor.catalog_digest
            or current_snapshot.diagnostic_bundle_digest != descriptor.bundle_digest
            or descriptor.diagnostic_order != _DIAGNOSTIC_ORDER
            or descriptor.attack_path_issue_sequences != _PATH_ORDER
        ):
            raise ValueError("advisory topology differs from installed profile or bundle pins")
        plan_digest = _plan_digest(
            source_run_id=expected_source_run_id,
            source_root_digest=expected_source_root_digest,
            source_snapshot_digest=current_snapshot.snapshot_digest,
            bridge_digest=record.bridge_digest,
            receipt_digest=record.receipt_digest,
            compiled_proposal_digest=verified.proposal_digest,
            profile_digest=profile.profile_digest,
            diagnostic_catalog_digest=descriptor.catalog_digest,
            diagnostic_bundle_digest=descriptor.bundle_digest,
        )
        payload: dict[str, object] = {
            "apiVersion": GOVERNED_WEB_ADVISORY_TOPOLOGY_API_VERSION,
            "kind": "GovernedWebAdvisoryTopology",
            "planDigest": plan_digest,
            "sourceRunId": expected_source_run_id,
            "sourceRootDigest": expected_source_root_digest,
            "sourceSnapshotDigest": current_snapshot.snapshot_digest,
            "bridgeDigest": record.bridge_digest,
            "receiptDigest": record.receipt_digest,
            "compiledProposalDigest": verified.proposal_digest,
            "profileDigest": profile.profile_digest,
            "diagnosticCatalogDigest": descriptor.catalog_digest,
            "diagnosticBundleDigest": descriptor.bundle_digest,
            "diagnosticOrder": _DIAGNOSTIC_ORDER,
            "attackPathOrder": _PATH_ORDER,
            "stageSlots": (_slot("source", plan_digest), _slot("validation", plan_digest)),
            "state": "candidate-topology-not-authorized",
            "diagnosticRankIsExecutionOrder": False,
            "scopeExpansionAuthorized": False,
            "modelCallAuthorized": False,
            "targetRequestAuthorized": False,
            "capabilityGranted": False,
            "approvalRecorded": False,
            "permitGranted": False,
            "executionAuthorized": False,
            "findingAuthorized": False,
            "graphAdmissionAuthorized": False,
            "reportAuthorized": False,
        }
        return GovernedWebAdvisoryTopology.model_validate(
            {**payload, "topologyDigest": discovery_digest(_TOPOLOGY_DOMAIN, payload)}
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise GovernedWebAdvisoryTopologyError(
            "governed Web advisory topology failed closed"
        ) from exc


__all__ = [
    "GOVERNED_WEB_ADVISORY_TOPOLOGY_API_VERSION",
    "GovernedWebAdvisoryStageSlot",
    "GovernedWebAdvisoryTopology",
    "GovernedWebAdvisoryTopologyError",
    "build_governed_web_advisory_topology",
]
