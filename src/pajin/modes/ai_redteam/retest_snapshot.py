"""Verified KISA retest snapshot loading and baseline read models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    Finding,
    ToolRequest,
    ToolResult,
)
from pajin.domain.orchestration import TaskGraph
from pajin.domain.validation import (
    CandidateFinding,
    ConfirmationBasis,
    FindingDisposition,
    ValidationDecision,
    ValidationMethod,
)
from pajin.modes.ai_redteam.models import KISAAssessment
from pajin.runtime.store import (
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json
from pajin.runtime.worker import WorkerResult
from pajin.tools.ai import evaluate_trusted_regression
from pajin.workflow.validation_artifacts import (
    VERSIONED_VALIDATION_INDEX_PATH,
    LoadedValidationSnapshot,
    ValidationSnapshotSemantics,
    load_validation_snapshot,
)

_MAX_MANAGED_JSON_BYTES = 64 * 1024 * 1024
_MAX_TOOL_EVIDENCE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class _EvidenceRecord:
    relative_path: str
    request: ToolRequest | None
    result: ToolResult | None
    worker_result: WorkerResult | None
    tool_id: str
    success: bool
    threat_class: str | None
    vulnerable: bool | None
    regression_passed: bool | None
    trusted_regression_passed: bool | None
    network_log_trusted: bool
    backend: str | None


@dataclass(frozen=True)
class _RunSnapshot:
    path: Path
    run_id: str
    campaign: CampaignManifest
    plan: AgentPlan
    task_graph: TaskGraph
    assessment: KISAAssessment | None
    findings: list[Finding]
    evidence: list[_EvidenceRecord]
    validation_snapshot: LoadedValidationSnapshot
    root_digest: str
    verified: VerifiedRunSnapshot


@dataclass(frozen=True)
class _ConfirmedBaselineRecord:
    candidate: CandidateFinding
    decision: ValidationDecision
    finding: Finding


class KISARetestSnapshotReader:
    """Load one immutable KISA Run and validate its retest authority model."""

    def load(
        self,
        path: Path,
        *,
        require_confirmed_baseline: bool = False,
    ) -> _RunSnapshot:
        resolved = path.resolve()
        initial = load_verified_run_snapshot(resolved)
        sealed_paths = {artifact.path for seal in initial.seals for artifact in seal.artifacts}
        self._validate_snapshot_artifacts(
            sealed_paths,
            require_confirmed_baseline=require_confirmed_baseline,
        )
        metadata_requests = {
            "run.json": _MAX_MANAGED_JSON_BYTES,
            "campaign.json": _MAX_MANAGED_JSON_BYTES,
            "findings.json": _MAX_MANAGED_JSON_BYTES,
            "plan.json": _MAX_MANAGED_JSON_BYTES,
            "task-graph.json": _MAX_MANAGED_JSON_BYTES,
        }
        for optional_path in ("kisa-results.json", "remediation-plan.json"):
            if optional_path in sealed_paths:
                metadata_requests[optional_path] = _MAX_MANAGED_JSON_BYTES
        metadata = load_verified_run_artifacts(
            resolved,
            requests=metadata_requests,
            expected_run_id=initial.verification.run_id,
        )
        require_same_authority(
            initial,
            metadata,
            message="sealed KISA Run changed while retest inputs were loaded",
        )
        run = self._completed_run_summary(metadata)
        validation_snapshot = load_validation_snapshot(
            resolved,
            verified_snapshot=metadata,
        )
        evidence_requests = {
            relative_path: _MAX_TOOL_EVIDENCE_BYTES
            for relative_path in sealed_paths
            if relative_path.startswith("evidence/")
            and relative_path.endswith(".json")
            and len(relative_path.split("/")) == 2
        }
        verified = load_verified_run_artifacts(
            resolved,
            requests={**metadata_requests, **evidence_requests},
            expected_run_id=initial.verification.run_id,
        )
        require_same_authority(
            metadata,
            verified,
            message="sealed KISA Run changed while retest inputs were loaded",
        )
        snapshot = _RunSnapshot(
            path=resolved,
            run_id=str(run["runId"]),
            campaign=CampaignManifest.model_validate(
                strict_json(
                    verified,
                    "campaign.json",
                    label="KISA campaign",
                    max_bytes=_MAX_MANAGED_JSON_BYTES,
                )
            ),
            plan=AgentPlan.model_validate(
                strict_json(
                    verified,
                    "plan.json",
                    label="KISA plan",
                    max_bytes=_MAX_MANAGED_JSON_BYTES,
                )
            ),
            task_graph=TaskGraph.model_validate(
                strict_json(
                    verified,
                    "task-graph.json",
                    label="KISA task graph",
                    max_bytes=_MAX_MANAGED_JSON_BYTES,
                )
            ),
            assessment=(
                KISAAssessment.model_validate(
                    strict_json(
                        verified,
                        "kisa-results.json",
                        label="KISA assessment",
                        max_bytes=_MAX_MANAGED_JSON_BYTES,
                    )
                )
                if "kisa-results.json" in verified.artifacts
                else None
            ),
            findings=validation_snapshot.product_confirmed_findings,
            evidence=self._load_evidence_records(verified),
            validation_snapshot=validation_snapshot,
            root_digest=verified.verification.root_digest,
            verified=verified,
        )
        if snapshot.run_id != verified.verification.run_id:
            raise ValueError("sealed run.json identifier differs from the Run integrity chain")
        self._validate_assessment_projection(snapshot)
        if require_confirmed_baseline:
            self._validate_confirmed_baseline_snapshot(snapshot)
        return snapshot

    @staticmethod
    def require_current(snapshot: _RunSnapshot, *, label: str) -> None:
        observed = load_verified_run_snapshot(
            snapshot.path,
            expected_run_id=snapshot.run_id,
        )
        require_same_authority(snapshot.verified, observed, message=label)

    @staticmethod
    def confirmed_baseline_records(
        baseline: _RunSnapshot,
    ) -> tuple[_ConfirmedBaselineRecord, ...]:
        validation = baseline.validation_snapshot
        if (
            validation.semantics is not ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY
            or validation.index is None
        ):
            raise ValueError(
                "baseline requires sealed validation/v1alpha1 verified replay semantics"
            )
        candidates = {
            candidate.candidate_id: candidate for candidate in validation.validation.candidates
        }
        decisions = [
            decision
            for decision in validation.validation.decisions
            if decision.disposition is FindingDisposition.CONFIRMED
        ]
        findings = {finding.finding_id: finding for finding in baseline.findings}
        records: list[_ConfirmedBaselineRecord] = []
        for decision in decisions:
            candidate = candidates.get(decision.candidate_id)
            if candidate is None:
                raise ValueError("Confirmed Decision has no exact baseline Candidate")
            finding = findings.get(candidate.claim.finding_id)
            expected_finding = candidate.claim.model_copy(update={"validated": True})
            if (
                finding is None
                or finding != expected_finding
                or decision.confirmation_basis is not ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY
                or decision.method is not ValidationMethod.RESTRICTED_REPLAY_GATE
                or not decision.replay_lineage
            ):
                raise ValueError(
                    "baseline Confirmed Candidate, Decision, Finding, and replay lineage differ"
                )
            records.append(
                _ConfirmedBaselineRecord(
                    candidate=candidate,
                    decision=decision,
                    finding=finding,
                )
            )
        if len(records) != len(baseline.findings):
            raise ValueError("baseline Confirmed Decision and Finding sets differ")
        if [record.candidate.candidate_id for record in records] != (
            validation.index.confirmed_candidate_ids
        ):
            raise ValueError("baseline Confirmed Candidate order differs from validation index")
        return tuple(records)

    @staticmethod
    def validate_comparable(baseline: _RunSnapshot, retest: _RunSnapshot) -> None:
        if baseline.run_id == retest.run_id:
            raise ValueError("baseline and retest must be different runs")
        baseline_targets = {target.endpoint for target in baseline.campaign.spec.targets}
        retest_targets = {target.endpoint for target in retest.campaign.spec.targets}
        if baseline_targets != retest_targets:
            raise ValueError("baseline and retest targets differ")
        if baseline.campaign.spec.mode is not retest.campaign.spec.mode:
            raise ValueError("baseline and retest Campaign modes differ")
        if set(baseline.campaign.spec.threat_classes) != set(retest.campaign.spec.threat_classes):
            raise ValueError("baseline and retest requested KISA threats differ")

    @staticmethod
    def _validate_snapshot_artifacts(
        sealed_paths: set[str],
        *,
        require_confirmed_baseline: bool,
    ) -> None:
        required = {
            "run.json",
            "campaign.json",
            "findings.json",
            "plan.json",
            "task-graph.json",
        }
        if require_confirmed_baseline:
            required.add("kisa-results.json")
        missing = sorted(required - sealed_paths)
        if missing:
            raise ValueError(f"run is missing required artifacts: {missing}")

    @staticmethod
    def _completed_run_summary(snapshot: VerifiedRunSnapshot) -> dict[str, object]:
        run = strict_json(
            snapshot,
            "run.json",
            label="KISA Run state",
            max_bytes=_MAX_MANAGED_JSON_BYTES,
            expected_type=dict,
            type_message="sealed run.json must contain an object",
        )
        if run.get("status") != "completed":
            raise ValueError("KISA retest comparison requires completed runs")
        return run

    def _load_evidence_records(
        self,
        snapshot: VerifiedRunSnapshot,
    ) -> list[_EvidenceRecord]:
        return [
            self._load_evidence_record(snapshot, relative_path)
            for relative_path in sorted(snapshot.artifacts)
            if relative_path.startswith("evidence/")
            and relative_path.endswith(".json")
            and len(relative_path.split("/")) == 2
        ]

    def _load_evidence_record(
        self,
        snapshot: VerifiedRunSnapshot,
        relative_path: str,
    ) -> _EvidenceRecord:
        payload = strict_json(
            snapshot,
            relative_path,
            label="AI evidence",
            max_bytes=_MAX_MANAGED_JSON_BYTES,
            expected_type=dict,
            type_message="AI evidence must contain an object",
        )
        result = payload.get("result", {})
        data = result.get("data", {}) if isinstance(result, dict) else {}
        request = payload.get("request", {})
        worker = payload.get("workerResult", {})
        network_log_trusted = payload.get("networkLogTrusted", False)
        if not isinstance(network_log_trusted, bool):
            raise ValueError("AI evidence network-log trust marker must be boolean")
        typed_request = ToolRequest.model_validate(request) if isinstance(request, dict) else None
        typed_result = ToolResult.model_validate(result) if isinstance(result, dict) else None
        typed_worker = (
            WorkerResult.model_validate(worker) if isinstance(worker, dict) and worker else None
        )
        return _EvidenceRecord(
            relative_path=relative_path,
            request=typed_request,
            result=typed_result,
            worker_result=typed_worker,
            tool_id=self._evidence_tool_id(typed_request, typed_result),
            success=typed_result.success if typed_result is not None else False,
            threat_class=self._typed_evidence_value(data, "threatClass", str),
            vulnerable=self._typed_evidence_value(data, "vulnerable", bool),
            regression_passed=self._typed_evidence_value(data, "regressionPassed", bool),
            trusted_regression_passed=self._trusted_regression_result(
                typed_request,
                typed_result,
                typed_worker,
                network_log_trusted=network_log_trusted,
            ),
            network_log_trusted=network_log_trusted,
            backend=typed_worker.backend if typed_worker is not None else None,
        )

    def _validate_confirmed_baseline_snapshot(self, snapshot: _RunSnapshot) -> None:
        if (
            snapshot.validation_snapshot.semantics
            is not ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY
        ):
            raise ValueError(
                "baseline requires sealed validation/v1alpha1 VERIFIED_INDEPENDENT_REPLAY semantics"
            )
        if not snapshot.findings:
            raise ValueError("baseline has no reproduction-backed Confirmed findings to remediate")
        if snapshot.assessment is None:
            raise ValueError("baseline requires a sealed KISA assessment")
        self.confirmed_baseline_records(snapshot)

    @staticmethod
    def _validate_assessment_projection(snapshot: _RunSnapshot) -> None:
        validation = snapshot.validation_snapshot
        assessment = snapshot.assessment
        if assessment is None:
            return
        expected_version = (
            validation.index.api_version if validation.index is not None else "legacy-unversioned"
        )
        expected_artifact = (
            VERSIONED_VALIDATION_INDEX_PATH if validation.index is not None else None
        )
        expected_finding_ids = [finding.finding_id for finding in snapshot.findings]
        if assessment.run_id != snapshot.run_id:
            raise ValueError("KISA assessment belongs to another Run")
        if (
            assessment.validation_artifact_version != expected_version
            or assessment.confirmation_semantics != validation.semantics.value
            or assessment.confirmation_artifact != expected_artifact
            or assessment.confirmed_finding_ids != expected_finding_ids
        ):
            raise ValueError(
                "KISA assessment confirmation semantics and IDs differ from validation artifacts"
            )

    @staticmethod
    def _evidence_tool_id(
        request: ToolRequest | None,
        result: ToolResult | None,
    ) -> str:
        if result is not None:
            return result.tool_id
        return request.tool_id if request is not None else ""

    @staticmethod
    def _typed_evidence_value[T](
        data: object,
        field: str,
        expected_type: type[T],
    ) -> T | None:
        if not isinstance(data, dict):
            return None
        value = data.get(field)
        return value if isinstance(value, expected_type) else None

    @staticmethod
    def _trusted_regression_result(
        request: ToolRequest | None,
        result: ToolResult | None,
        worker: WorkerResult | None,
        *,
        network_log_trusted: bool,
    ) -> bool | None:
        is_regression = (request is not None and request.tool_id == "ai.normal-probe") or (
            result is not None and result.tool_id == "ai.normal-probe"
        )
        if not is_regression:
            return None
        if request is None or result is None:
            raise ValueError("AI regression evidence is missing its request or Tool result")
        if result.request_id != request.request_id or result.tool_id != request.tool_id:
            raise ValueError("AI regression Tool result identity differs from its request")
        if not result.success:
            return None
        if worker is None:
            raise ValueError("successful AI regression evidence is missing raw Worker stdout")
        return evaluate_trusted_regression(
            request,
            result,
            worker,
            network_log_trusted=network_log_trusted,
        )
