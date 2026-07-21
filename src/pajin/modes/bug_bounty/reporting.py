"""Evidence-bound Bug Bounty finding deduplication and submission drafts."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path, PurePosixPath
from re import fullmatch
from typing import ClassVar
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CampaignMode,
    Finding,
    StrictModel,
)
from pajin.domain.validation import (
    CandidateFinding,
    FindingDisposition,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
)
from pajin.domain.yaml_loader import load_yaml_mapping
from pajin.modes.bug_bounty.models import (
    BugBountyProbeProfile,
    BugBountyProgramManifest,
)
from pajin.modes.bug_bounty.service import BugBountyScopeService
from pajin.policy.scope import normalize_target_url, scope_matches
from pajin.reporting import escape_markdown_text, markdown_code_span
from pajin.runtime.store import (
    AuditEvent,
    RunIntegrityError,
    RunStore,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json
from pajin.workflow.validation_artifacts import (
    LoadedValidationSnapshot,
    ValidationSnapshotSemantics,
    load_validation_snapshot,
)

_MAX_MANAGED_JSON_BYTES = 64 * 1024 * 1024
_MAX_MANAGED_EVIDENCE_BYTES = 64 * 1024 * 1024


class KnownFindingStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"


class KnownBugBountyFinding(StrictModel):
    external_id: str = Field(alias="externalId", min_length=1, max_length=120)
    target: str
    vulnerability_class: str = Field(alias="vulnerabilityClass", min_length=1, max_length=120)
    affected_component: str = Field(alias="affectedComponent", min_length=1, max_length=500)
    root_cause: str = Field(alias="rootCause", min_length=1, max_length=1_000)
    status: KnownFindingStatus
    reference: str | None = Field(default=None, max_length=2_048)

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return normalize_target_url(value)

    @field_validator("reference")
    @classmethod
    def validate_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = normalize_target_url(value)
        if not normalized.startswith("https://"):
            raise ValueError("known finding reference must use HTTPS")
        return normalized


class BugBountyFindingIndex(StrictModel):
    api_version: str = Field(alias="apiVersion", pattern=r"^pajin\.dev/v\d+(alpha\d+|beta\d+)?$")
    kind: str = Field(pattern=r"^BugBountyFindingIndex$")
    program_name: str = Field(alias="programName", pattern=r"^[a-z0-9][a-z0-9-]*$")
    findings: list[KnownBugBountyFinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_unique_external_ids(self) -> BugBountyFindingIndex:
        identifiers = [finding.external_id for finding in self.findings]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("known Bug Bounty externalId values must be unique")
        return self


class DuplicateDisposition(StrEnum):
    READY = "ready"
    NEEDS_REVIEW = "needs-review"
    KNOWN_DUPLICATE = "known-duplicate"
    RUN_DUPLICATE = "run-duplicate"


class BugBountyValidationAuthority(StrEnum):
    VERIFIED_INDEPENDENT_REPLAY = "verified-independent-replay"
    SEMANTIC_REVIEW_ONLY = "semantic-review-only"


class BugBountyTriageItem(StrictModel):
    finding: Finding
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    cause_fingerprint: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    disposition: DuplicateDisposition
    validation_authority: BugBountyValidationAuthority
    duplicate_candidates: list[str] = Field(default_factory=list)
    missing_fields: list[str] = Field(default_factory=list)
    submission_eligible: bool = False
    draft_path: str | None = None

    @model_validator(mode="after")
    def enforce_submission_authority(self) -> BugBountyTriageItem:
        eligible = (
            self.disposition is DuplicateDisposition.READY
            and self.validation_authority
            is BugBountyValidationAuthority.VERIFIED_INDEPENDENT_REPLAY
        )
        if self.submission_eligible != eligible:
            raise ValueError(
                "submission eligibility requires a ready independently replayed Finding"
            )
        return self


class BugBountyTriageSummary(StrictModel):
    total: int = Field(ge=0)
    ready: int = Field(ge=0)
    needs_review: int = Field(ge=0)
    known_duplicates: int = Field(ge=0)
    run_duplicates: int = Field(ge=0)


class BugBountyTriageReport(StrictModel):
    report_id: str
    run_id: str
    program_name: str
    scope_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    generated_at: datetime
    severity_standard: str
    summary: BugBountyTriageSummary
    items: list[BugBountyTriageItem]


class BugBountyReportArtifacts(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    directory: Path
    triage_path: Path
    report_path: Path
    submission_paths: list[Path]
    report: BugBountyTriageReport


class _RunSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    run_id: str
    path: Path
    campaign: CampaignManifest
    findings: list[Finding]
    review_only_finding_ids: frozenset[str]
    evidence_paths: frozenset[str]
    started_at: datetime
    completed_at: datetime


def load_bug_bounty_finding_index(path: Path) -> BugBountyFindingIndex:
    raw = load_yaml_mapping(path, label="Bug Bounty finding index")
    return BugBountyFindingIndex.model_validate(raw)


class BugBountyReportService:
    """Validate one completed run, deduplicate findings, and emit submission drafts."""

    _AUTO_DUPLICATE_STATUSES: ClassVar[frozenset[KnownFindingStatus]] = frozenset(
        {
            KnownFindingStatus.OPEN,
            KnownFindingStatus.TRIAGED,
            KnownFindingStatus.ACCEPTED,
            KnownFindingStatus.DUPLICATE,
        }
    )

    def validate_campaign(
        self,
        program: BugBountyProgramManifest,
        campaign: CampaignManifest,
    ) -> str:
        """Require an executable Campaign to match the current reviewed program policy."""

        review = BugBountyScopeService().review(program)
        self._validate_campaign_policy(program, campaign, review.scope_digest)
        return review.scope_digest

    def report_run(
        self,
        program: BugBountyProgramManifest,
        run_path: Path,
        *,
        known_findings: BugBountyFindingIndex | None = None,
        generated_at: datetime | None = None,
    ) -> BugBountyReportArtifacts:
        snapshot = self._load_snapshot(program, run_path)
        if known_findings is not None and known_findings.program_name != program.metadata.name:
            raise ValueError("known finding index belongs to a different Bug Bounty program")
        scope_digest = self.validate_campaign(program, snapshot.campaign)
        for finding in snapshot.findings:
            self._validate_finding(
                snapshot,
                finding,
                review_only=finding.finding_id in snapshot.review_only_finding_ids,
            )

        items = self._triage(
            program,
            snapshot.findings,
            known_findings.findings if known_findings is not None else [],
            duplicate_check_performed=known_findings is not None,
            review_only_finding_ids=snapshot.review_only_finding_ids,
        )
        generated = generated_at or datetime.now(UTC)
        report_id = self._report_id(snapshot.run_id, scope_digest, items, known_findings)
        relative_directory = f"bug-bounty-reports/{report_id}"
        directory = snapshot.path / relative_directory
        if directory.exists():
            raise ValueError(f"Bug Bounty report already exists for this input: {report_id}")

        submission_paths: list[Path] = []
        for item in items:
            if item.disposition in {
                DuplicateDisposition.KNOWN_DUPLICATE,
                DuplicateDisposition.RUN_DUPLICATE,
            }:
                continue
            finding_slug = self._safe_finding_slug(item.finding.finding_id)
            item.draft_path = f"{relative_directory}/submissions/{finding_slug}.md"
            submission_paths.append(snapshot.path / item.draft_path)

        summary = self._summary(items)
        report = BugBountyTriageReport(
            report_id=report_id,
            run_id=snapshot.run_id,
            program_name=program.metadata.name,
            scope_digest=scope_digest,
            generated_at=generated,
            severity_standard=program.spec.reporting.severity_standard,
            summary=summary,
            items=items,
        )
        store = RunStore(run_id=snapshot.run_id, path=snapshot.path)
        triage_relative = store.write_json(
            f"{relative_directory}/bug-bounty-triage.json",
            report.model_dump(mode="json"),
        )
        report_relative = store.write_text(
            f"{relative_directory}/bug-bounty-report.md",
            self._render_report(program, report),
        )
        for item in items:
            if item.draft_path is not None:
                store.write_text(item.draft_path, self._render_submission(program, item))
        store.append_event(
            "mode-pack.bug-bounty.reported",
            {
                "reportId": report_id,
                "triage": triage_relative,
                "report": report_relative,
                "ready": summary.ready,
                "needsReview": summary.needs_review,
                "knownDuplicates": summary.known_duplicates,
                "runDuplicates": summary.run_duplicates,
            },
        )
        store.seal()
        return BugBountyReportArtifacts(
            directory=directory,
            triage_path=snapshot.path / triage_relative,
            report_path=snapshot.path / report_relative,
            submission_paths=submission_paths,
            report=report,
        )

    def _triage(
        self,
        program: BugBountyProgramManifest,
        findings: list[Finding],
        known_findings: list[KnownBugBountyFinding],
        *,
        duplicate_check_performed: bool,
        review_only_finding_ids: frozenset[str],
    ) -> list[BugBountyTriageItem]:
        bounty_eligible_targets = {
            entry_point
            for asset in program.spec.scope.in_scope
            if asset.eligible_for_bounty
            for entry_point in asset.entry_points
        }
        known_exact: dict[str, list[KnownBugBountyFinding]] = defaultdict(list)
        known_cause: dict[str, list[KnownBugBountyFinding]] = defaultdict(list)
        for known in known_findings:
            exact, cause = self._known_fingerprints(program.metadata.name, known)
            known_exact[exact].append(known)
            known_cause[cause].append(known)

        ordered = sorted(
            findings,
            key=lambda finding: (
                finding.finding_id in review_only_finding_ids,
                -finding.confidence,
                finding.finding_id,
            ),
        )
        seen_exact: dict[str, str] = {}
        items: list[BugBountyTriageItem] = []
        for finding in ordered:
            fingerprint, cause_fingerprint = self._finding_fingerprints(
                program.metadata.name,
                finding,
            )
            missing = self._missing_fields(
                program,
                finding,
                bounty_eligible_targets=bounty_eligible_targets,
                duplicate_check_performed=duplicate_check_performed,
                review_only=finding.finding_id in review_only_finding_ids,
            )
            candidates: set[str] = set()
            disposition = DuplicateDisposition.READY

            exact_known = known_exact.get(fingerprint, [])
            auto_known = [
                item for item in exact_known if item.status in self._AUTO_DUPLICATE_STATUSES
            ]
            if auto_known:
                disposition = DuplicateDisposition.KNOWN_DUPLICATE
                candidates.update(item.external_id for item in auto_known)
            elif fingerprint in seen_exact:
                disposition = DuplicateDisposition.RUN_DUPLICATE
                candidates.add(seen_exact[fingerprint])
            else:
                seen_exact[fingerprint] = finding.finding_id
                if exact_known:
                    candidates.update(item.external_id for item in exact_known)
                if cause_fingerprint is not None:
                    candidates.update(
                        item.external_id
                        for item in known_cause.get(cause_fingerprint, [])
                        if self._known_fingerprints(program.metadata.name, item)[0] != fingerprint
                    )
                if missing or candidates:
                    disposition = DuplicateDisposition.NEEDS_REVIEW

            items.append(
                BugBountyTriageItem(
                    finding=finding,
                    fingerprint=fingerprint,
                    cause_fingerprint=cause_fingerprint,
                    disposition=disposition,
                    validation_authority=(
                        BugBountyValidationAuthority.SEMANTIC_REVIEW_ONLY
                        if finding.finding_id in review_only_finding_ids
                        else BugBountyValidationAuthority.VERIFIED_INDEPENDENT_REPLAY
                    ),
                    duplicate_candidates=sorted(candidates),
                    missing_fields=missing,
                    submission_eligible=(
                        disposition is DuplicateDisposition.READY
                        and finding.finding_id not in review_only_finding_ids
                    ),
                )
            )

        cause_groups: dict[str, list[BugBountyTriageItem]] = defaultdict(list)
        for item in items:
            if item.cause_fingerprint is not None:
                cause_groups[item.cause_fingerprint].append(item)
        for group in cause_groups.values():
            exact_fingerprints = {item.fingerprint for item in group}
            if len(exact_fingerprints) <= 1:
                continue
            for item in group:
                if item.disposition not in {
                    DuplicateDisposition.READY,
                    DuplicateDisposition.NEEDS_REVIEW,
                }:
                    continue
                item.disposition = DuplicateDisposition.NEEDS_REVIEW
                item.submission_eligible = False
                peer_ids = {
                    peer.finding.finding_id
                    for peer in group
                    if peer.fingerprint != item.fingerprint
                }
                item.duplicate_candidates = sorted(set(item.duplicate_candidates) | peer_ids)
        return items

    @staticmethod
    def _missing_fields(
        program: BugBountyProgramManifest,
        finding: Finding,
        *,
        bounty_eligible_targets: set[str],
        duplicate_check_performed: bool,
        review_only: bool,
    ) -> list[str]:
        field_presence = {
            "affected-component": bool(finding.affected_component),
            "confidence": finding.confidence >= 0,
            "evidence": bool(finding.evidence),
            "impact": bool(finding.impact),
            "remediation": bool(finding.remediation),
            "reproduction": bool(finding.reproduction),
            "root-cause": bool(finding.root_cause),
            "severity": bool(finding.severity.value),
            "summary": bool(finding.summary),
            "target": bool(finding.target),
            "title": bool(finding.title),
            "vulnerability-class": bool(finding.threat_class),
        }
        missing = {
            name for name in program.spec.reporting.required_fields if not field_presence[name]
        }
        if not finding.affected_component:
            missing.add("dedup-affected-component")
        if not finding.root_cause:
            missing.add("dedup-root-cause")
        if finding.target not in bounty_eligible_targets:
            missing.add("target-not-bounty-eligible")
        if program.spec.reporting.duplicate_check_required and not duplicate_check_performed:
            missing.add("duplicate-check-not-performed")
        if review_only:
            missing.add("independent-reproduction-not-confirmed")
        return sorted(missing)

    @staticmethod
    def _finding_fingerprints(
        program_name: str,
        finding: Finding,
    ) -> tuple[str, str | None]:
        component = BugBountyReportService._label(finding.affected_component)
        root_cause = BugBountyReportService._label(finding.root_cause)
        vulnerability_class = BugBountyReportService._label(finding.threat_class)
        target_identity, authority = BugBountyReportService._target_identities(finding.target)
        if component is None or root_cause is None:
            unique_unknown = f"unknown:{finding.finding_id}"
            exact = BugBountyReportService._fingerprint(
                program_name,
                target_identity,
                vulnerability_class or unique_unknown,
                component or unique_unknown,
                root_cause or unique_unknown,
            )
            return exact, None
        exact = BugBountyReportService._fingerprint(
            program_name,
            target_identity,
            vulnerability_class or "unknown",
            component,
            root_cause,
        )
        cause = BugBountyReportService._fingerprint(
            program_name,
            authority,
            vulnerability_class or "unknown",
            component,
            root_cause,
        )
        return exact, cause

    @staticmethod
    def _known_fingerprints(
        program_name: str,
        finding: KnownBugBountyFinding,
    ) -> tuple[str, str]:
        target_identity, authority = BugBountyReportService._target_identities(finding.target)
        vulnerability_class = BugBountyReportService._label(finding.vulnerability_class)
        component = BugBountyReportService._label(finding.affected_component)
        root_cause = BugBountyReportService._label(finding.root_cause)
        assert vulnerability_class is not None
        assert component is not None
        assert root_cause is not None
        return (
            BugBountyReportService._fingerprint(
                program_name,
                target_identity,
                vulnerability_class,
                component,
                root_cause,
            ),
            BugBountyReportService._fingerprint(
                program_name,
                authority,
                vulnerability_class,
                component,
                root_cause,
            ),
        )

    @staticmethod
    def _target_identities(target: str) -> tuple[str, str]:
        normalized = normalize_target_url(target)
        parsed = urlsplit(normalized)
        query_keys = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        target_identity = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, "&".join(query_keys), "")
        )
        authority = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
        return target_identity, authority

    @staticmethod
    def _fingerprint(*parts: str) -> str:
        material = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))
        return sha256(material.encode("utf-8")).hexdigest()

    @staticmethod
    def _label(value: str | None) -> str | None:
        if value is None:
            return None
        normalized = " ".join(value.casefold().split())
        return normalized or None

    @staticmethod
    def _validate_finding(
        snapshot: _RunSnapshot,
        finding: Finding,
        *,
        review_only: bool,
    ) -> None:
        if review_only and finding.validated:
            raise ValueError(
                f"review-only Candidate is incorrectly marked validated: {finding.finding_id}"
            )
        if not review_only and not finding.validated:
            raise ValueError(f"finding is not independently validated: {finding.finding_id}")
        targets = {target.endpoint for target in snapshot.campaign.spec.targets}
        if finding.target not in targets:
            raise ValueError(f"finding target is not declared by the run: {finding.finding_id}")
        scope = snapshot.campaign.spec.scope
        if any(scope_matches(rule, finding.target) for rule in scope.deny):
            raise ValueError(f"finding target matches run deny scope: {finding.finding_id}")
        if not any(scope_matches(rule, finding.target) for rule in scope.allow):
            raise ValueError(f"finding target is outside run allow scope: {finding.finding_id}")
        for relative in finding.evidence:
            if relative not in snapshot.evidence_paths:
                raise ValueError(
                    f"finding evidence is missing or outside this run: {finding.finding_id}"
                )

    @staticmethod
    def _validate_campaign_policy(
        program: BugBountyProgramManifest,
        campaign: CampaignManifest,
        scope_digest: str,
    ) -> None:
        if campaign.spec.mode is not CampaignMode.BUG_BOUNTY:
            raise ValueError("Bug Bounty reporting requires mode: bug-bounty")
        if campaign.metadata.name != program.metadata.name:
            raise ValueError("run campaign belongs to a different Bug Bounty program")
        marker = f"scope-sha256:{scope_digest}"
        evidence_tokens = {part.strip() for part in campaign.spec.authorization.evidence.split(";")}
        if marker not in evidence_tokens:
            raise ValueError("run campaign is not approved for the current program policy digest")

        review = BugBountyScopeService().review(program)
        rules = campaign.spec.rules_of_engagement
        expected_targets: list[tuple[str, str, str, dict[str, object]]] = []
        for asset in program.spec.scope.in_scope:
            for index, entry_point in enumerate(asset.entry_points, start=1):
                suffix = "" if len(asset.entry_points) == 1 else f"-{index}"
                target_type = (
                    "bug-bounty-api"
                    if asset.probe_profile is BugBountyProbeProfile.BOOLEAN_SQLI_LAB
                    else "http"
                )
                expected_targets.append((target_type, f"{asset.asset_id}{suffix}", entry_point, {}))
        observed_targets = [
            (target.type, target.id, target.endpoint, target.simulation)
            for target in campaign.spec.targets
        ]
        policy_matches = (
            campaign.spec.scope.allow == review.allow
            and campaign.spec.scope.deny == review.deny
            and observed_targets == expected_targets
            and campaign.spec.autonomy is AutonomyLevel.SUPERVISED
            and campaign.spec.access_profile == "blackbox"
            and sorted(campaign.spec.objectives) == sorted(program.spec.objectives)
            and not campaign.spec.threat_classes
            and rules.max_tool_risk_tier == program.spec.rules.max_tool_risk_tier
            and rules.allowed_methods == review.allowed_methods
            and rules.allowed_tool_categories == review.allowed_tool_categories
            and rules.prohibit == review.prohibited_techniques
            and rules.stop_on == review.stop_on
            and rules.allow_private_networks == program.spec.rules.allow_private_networks
            and rules.max_requests_per_minute == review.max_requests_per_minute
            and rules.testing_windows == review.testing_windows
            and campaign.spec.budgets == program.spec.budgets
        )
        if not policy_matches:
            raise ValueError("run campaign policy differs from the reviewed Bug Bounty policy")

    @staticmethod
    def _load_snapshot(
        program: BugBountyProgramManifest,
        run_path: Path,
    ) -> _RunSnapshot:
        resolved = run_path.resolve()
        initial = load_verified_run_snapshot(resolved)
        validation_snapshot = load_validation_snapshot(
            resolved,
            verified_snapshot=initial,
        )
        sealed_paths = {artifact.path for seal in initial.seals for artifact in seal.artifacts}
        required = {"campaign.json", "findings.json"}
        missing = sorted(required - sealed_paths)
        if missing:
            raise ValueError(f"run is missing required artifacts: {missing}")

        metadata_requests = {
            "campaign.json": _MAX_MANAGED_JSON_BYTES,
            "findings.json": _MAX_MANAGED_JSON_BYTES,
        }
        if "run.json" in sealed_paths:
            metadata_requests["run.json"] = _MAX_MANAGED_JSON_BYTES
        metadata = load_verified_run_artifacts(
            resolved,
            requests=metadata_requests,
            expected_run_id=initial.verification.run_id,
        )
        require_same_authority(
            initial,
            metadata,
            message="sealed Bug Bounty Run changed while report inputs were derived",
        )

        campaign_raw = strict_json(
            metadata,
            "campaign.json",
            label="Bug Bounty campaign artifact",
            max_bytes=_MAX_MANAGED_JSON_BYTES,
        )
        campaign = CampaignManifest.model_validate(campaign_raw)
        if campaign.metadata.name != program.metadata.name:
            raise ValueError("run campaign belongs to a different Bug Bounty program")

        findings_raw = strict_json(
            metadata,
            "findings.json",
            label="Bug Bounty findings artifact",
            max_bytes=_MAX_MANAGED_JSON_BYTES,
            expected_type=list,
            type_message="findings.json must contain a list",
        )
        source_findings = [Finding.model_validate(item) for item in findings_raw]
        source_finding_ids = [finding.finding_id for finding in source_findings]
        if len(source_finding_ids) != len(set(source_finding_ids)):
            raise ValueError("findings.json contains duplicate finding identifiers")

        findings, review_only_finding_ids = BugBountyReportService._reportable_findings(
            validation_snapshot
        )
        finding_ids = [finding.finding_id for finding in findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("validation snapshot contains duplicate reportable Finding IDs")

        evidence_paths: set[str] = set()
        for finding in findings:
            for relative in finding.evidence:
                if not BugBountyReportService._is_canonical_evidence_path(relative):
                    raise ValueError(f"finding evidence is outside this run: {finding.finding_id}")
                evidence_paths.add(relative)
        evidence_requests = {relative: _MAX_MANAGED_EVIDENCE_BYTES for relative in evidence_paths}
        try:
            snapshot = load_verified_run_artifacts(
                resolved,
                requests={**metadata_requests, **evidence_requests},
                expected_run_id=initial.verification.run_id,
            )
        except (RunIntegrityError, ValueError) as exc:
            raise ValueError("finding evidence is missing or outside this Run") from exc
        require_same_authority(
            metadata,
            snapshot,
            message="sealed Bug Bounty Run changed while report inputs were derived",
        )

        completed_run_id, started_event, completed_event = (
            BugBountyReportService._load_campaign_lifecycle(snapshot.events, campaign)
        )

        if "run.json" in metadata_requests:
            run_state = strict_json(
                snapshot,
                "run.json",
                label="Bug Bounty Run state artifact",
                max_bytes=_MAX_MANAGED_JSON_BYTES,
                expected_type=dict,
                type_message="Bug Bounty report requires completed run state",
            )
            if run_state.get("status") != "completed":
                raise ValueError("Bug Bounty report requires completed run state")
            state_run_id = run_state.get("runId")
            if state_run_id != completed_run_id:
                raise ValueError("run state and completion event identifiers do not match")
        return _RunSnapshot(
            run_id=completed_run_id,
            path=resolved,
            campaign=campaign,
            findings=findings,
            review_only_finding_ids=review_only_finding_ids,
            evidence_paths=frozenset(evidence_paths),
            started_at=started_event.occurred_at,
            completed_at=completed_event.occurred_at,
        )

    @staticmethod
    def _reportable_findings(
        snapshot: LoadedValidationSnapshot,
    ) -> tuple[list[Finding], frozenset[str]]:
        confirmed = [
            finding.model_copy(deep=True) for finding in snapshot.product_confirmed_findings
        ]
        review_only: list[Finding] = []
        decisions = {decision.candidate_id: decision for decision in snapshot.validation.decisions}
        for candidate in snapshot.validation.candidates:
            decision = decisions[candidate.candidate_id]
            if not BugBountyReportService._is_semantically_supported_review(decision):
                continue
            BugBountyReportService._validate_review_authority(
                snapshot,
                candidate,
                decision,
            )
            review_only.append(candidate.claim.model_copy(deep=True, update={"validated": False}))
        review_ids = frozenset(finding.finding_id for finding in review_only)
        return [*confirmed, *review_only], review_ids

    @staticmethod
    def _is_semantically_supported_review(decision: ValidationDecision) -> bool:
        return bool(
            decision.disposition is FindingDisposition.NEEDS_REVIEW
            and decision.reason_codes
            in (
                [ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING],
                [ValidationReasonCode.INDEPENDENT_EXECUTION_ATTESTATION_MISSING],
            )
        )

    @staticmethod
    def _validate_review_authority(
        snapshot: LoadedValidationSnapshot,
        candidate: CandidateFinding,
        decision: ValidationDecision,
    ) -> None:
        claim = candidate.claim
        checks = {check.check_id: check for check in decision.checks}
        required_passes = {
            "target-declared",
            "threat-class-declared",
            "target-http-scope",
            "evidence-present",
            "evidence-result-links",
            "evidence-path-contained",
            "evidence-files",
            "evidence-provenance",
            "candidate-source-requests",
            "linked-executions",
        }
        passed = {
            check_id
            for check_id, check in checks.items()
            if check.status is ValidationCheckStatus.PASS
        }
        legacy_support = BugBountyReportService._check_passed_with_reason(
            checks,
            "legacy-validator-signal",
            ValidationReasonCode.VALIDATOR_CONFIRMED,
        )
        candidate_bound_support = BugBountyReportService._check_passed_with_reason(
            checks,
            "candidate-bound-validator-assessment",
            ValidationReasonCode.VALIDATOR_CONFIRMED,
        )
        reproduction = checks.get("independent-reproduction")
        reason = decision.reason_codes[0]
        if (
            not candidate.source_request_ids
            or not claim.evidence
            or decision.supporting_evidence != claim.evidence
            or decision.contradicting_evidence
            or not required_passes <= passed
            or not (legacy_support or candidate_bound_support)
            or reproduction is None
            or reproduction.status is not ValidationCheckStatus.FAIL
            or reproduction.reason_code is not reason
        ):
            raise ValueError(
                f"review-only Candidate lacks exact validation authority: {candidate.candidate_id}"
            )

        if reason is ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING:
            legacy_authority = bool(
                candidate.source == "legacy-validator-output"
                and candidate.source_agent_id == decision.validator_id
                and legacy_support
            )
            candidate_authority = bool(
                candidate.source.startswith("trusted-core:")
                and candidate.source_agent_id.startswith("trusted-core:")
                and candidate_bound_support
            )
            if (
                decision.method is not ValidationMethod.HYBRID_LEGACY_GATE
                or decision.confirmation_basis is not None
                or decision.replay_request_ids
                or decision.replay_outcome_ids
                or decision.replay_lineage
                or not (legacy_authority or candidate_authority)
            ):
                raise ValueError(
                    f"review-only Candidate has invalid source authority: {candidate.candidate_id}"
                )
            return

        replay_source_authority = bool(
            (candidate.source == "legacy-validator-output" and legacy_support)
            or (
                candidate.source.startswith("trusted-core:")
                and candidate.source_agent_id.startswith("trusted-core:")
                and candidate_bound_support
            )
        )
        if (
            snapshot.semantics is not ValidationSnapshotSemantics.VERIFIED_REPLAY_EVIDENCE
            or decision.method is not ValidationMethod.RESTRICTED_REPLAY_GATE
            or decision.validator_id != "trusted-core:confirmed-gate"
            or not decision.replay_lineage
            or decision.confirmation_basis is not None
            or not {"replay-receipt-integrity", "replay-lineage", "replay-oracle"} <= passed
            or not replay_source_authority
        ):
            raise ValueError(
                f"review-only Candidate has invalid replay authority: {candidate.candidate_id}"
            )

    @staticmethod
    def _check_passed_with_reason(
        checks: dict[str, ValidationCheckResult],
        check_id: str,
        reason: ValidationReasonCode,
    ) -> bool:
        check = checks.get(check_id)
        return bool(
            check is not None
            and check.status is ValidationCheckStatus.PASS
            and check.reason_code is reason
        )

    @staticmethod
    def _load_campaign_lifecycle(
        events: tuple[AuditEvent, ...],
        campaign: CampaignManifest,
    ) -> tuple[str, AuditEvent, AuditEvent]:
        run_ids = {event.run_id for event in events}
        if len(run_ids) != 1:
            raise ValueError("run event stream contains inconsistent run identifiers")
        started_events = [event for event in events if event.event_type == "campaign.started"]
        completed_events = [event for event in events if event.event_type == "campaign.completed"]
        if len(started_events) != 1 or len(completed_events) != 1:
            raise ValueError("Bug Bounty report requires a completed campaign run")
        started_event = started_events[0]
        completed_event = completed_events[0]
        if any(
            event.occurred_at.tzinfo is None or event.occurred_at.utcoffset() is None
            for event in (started_event, completed_event)
        ):
            raise ValueError("campaign lifecycle events must include a UTC offset or Z")
        if completed_event.occurred_at < started_event.occurred_at:
            raise ValueError("campaign completion event predates its start event")
        if not campaign.spec.authorization.is_active(started_event.occurred_at):
            raise ValueError("campaign authorization was not active when the run started")
        return completed_event.run_id, started_event, completed_event

    @staticmethod
    def _is_canonical_evidence_path(relative: str) -> bool:
        if not relative.startswith("evidence/") or "\\" in relative:
            return False
        path = PurePosixPath(relative)
        return (
            not path.is_absolute()
            and path.as_posix() == relative
            and all(part not in {"", ".", ".."} for part in relative.split("/"))
            and len(path.parts) > 1
        )

    @staticmethod
    def _summary(items: list[BugBountyTriageItem]) -> BugBountyTriageSummary:
        return BugBountyTriageSummary(
            total=len(items),
            ready=sum(item.disposition is DuplicateDisposition.READY for item in items),
            needs_review=sum(
                item.disposition is DuplicateDisposition.NEEDS_REVIEW for item in items
            ),
            known_duplicates=sum(
                item.disposition is DuplicateDisposition.KNOWN_DUPLICATE for item in items
            ),
            run_duplicates=sum(
                item.disposition is DuplicateDisposition.RUN_DUPLICATE for item in items
            ),
        )

    @staticmethod
    def _report_id(
        run_id: str,
        scope_digest: str,
        items: list[BugBountyTriageItem],
        known_findings: BugBountyFindingIndex | None,
    ) -> str:
        payload = {
            "runId": run_id,
            "scopeDigest": scope_digest,
            "items": [
                {
                    "findingId": item.finding.finding_id,
                    "finding": item.finding.model_dump(mode="json"),
                    "fingerprint": item.fingerprint,
                    "disposition": item.disposition.value,
                    "validationAuthority": item.validation_authority.value,
                    "submissionEligible": item.submission_eligible,
                    "candidates": item.duplicate_candidates,
                    "missing": item.missing_fields,
                }
                for item in items
            ],
            "known": (
                sorted(
                    (finding.model_dump(mode="json") for finding in known_findings.findings),
                    key=lambda finding: str(finding["external_id"]),
                )
                if known_findings
                else None
            ),
        }
        digest = sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return f"triage_{digest[:16]}"

    @staticmethod
    def _render_report(
        program: BugBountyProgramManifest,
        report: BugBountyTriageReport,
    ) -> str:
        summary = report.summary
        lines = [
            (
                "# Bug Bounty Triage Report: "
                + BugBountyReportService._text(program.metadata.display_name)
            ),
            "",
            f"- Report ID: {BugBountyReportService._code(report.report_id)}",
            f"- Run ID: {BugBountyReportService._code(report.run_id)}",
            f"- Scope digest: {BugBountyReportService._code(report.scope_digest)}",
            "- Severity standard: " + BugBountyReportService._code(report.severity_standard),
            f"- Ready for submission: {BugBountyReportService._code(str(summary.ready))}",
            f"- Needs review: {BugBountyReportService._code(str(summary.needs_review))}",
            "- Known duplicates: " + BugBountyReportService._code(str(summary.known_duplicates)),
            "- Same-run duplicates: " + BugBountyReportService._code(str(summary.run_duplicates)),
            "",
            "## Findings",
            "",
        ]
        if not report.items:
            lines.append(
                "No independently reproduced Findings or semantically supported review "
                "Candidates were present in this run."
            )
        for item in report.items:
            lines.extend(
                [
                    f"### {BugBountyReportService._text(item.finding.title)}",
                    "",
                    f"- Finding ID: {BugBountyReportService._code(item.finding.finding_id)}",
                    f"- Disposition: **{item.disposition.value}**",
                    "- Validation authority: "
                    + BugBountyReportService._code(item.validation_authority.value),
                    "- Submission eligible: "
                    + BugBountyReportService._code(str(item.submission_eligible).lower()),
                    f"- Fingerprint: {BugBountyReportService._code(item.fingerprint)}",
                    f"- Target: {BugBountyReportService._code(item.finding.target)}",
                    f"- Severity: {BugBountyReportService._code(item.finding.severity.value)}",
                ]
            )
            if item.duplicate_candidates:
                lines.append(
                    "- Duplicate candidates: "
                    + ", ".join(
                        BugBountyReportService._code(value) for value in item.duplicate_candidates
                    )
                )
            if item.missing_fields:
                lines.append(
                    "- Missing fields: "
                    + ", ".join(
                        BugBountyReportService._code(value) for value in item.missing_fields
                    )
                )
            if item.draft_path:
                lines.append(f"- Draft: {BugBountyReportService._code(item.draft_path)}")
            lines.append("")
        lines.extend(
            [
                "## Decision policy",
                "",
                "Only exact fingerprints matching an unresolved known finding or another finding "
                "in this run are suppressed automatically. Root-cause similarity produces "
                "`needs-review` and never suppresses a draft.",
                "",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _render_submission(
        program: BugBountyProgramManifest,
        item: BugBountyTriageItem,
    ) -> str:
        finding = item.finding
        lines = [
            f"# {BugBountyReportService._text(finding.title)}",
            "",
            (
                f"> Triage status: **{item.disposition.value}**. "
                "This is a draft, not an automatic submission."
            ),
            *(
                [
                    "> Review-only Candidate: semantic validation supported the exact claim, "
                    "but verified independent reproduction is not confirmed. This draft is "
                    "not submission-eligible."
                ]
                if item.validation_authority is BugBountyValidationAuthority.SEMANTIC_REVIEW_ONLY
                else []
            ),
            "",
            f"- Program: {BugBountyReportService._code(program.metadata.display_name)}",
            f"- Target: {BugBountyReportService._code(finding.target)}",
            (
                f"- Severity: {BugBountyReportService._code(finding.severity.value)} "
                f"({BugBountyReportService._text(program.spec.reporting.severity_standard)})"
            ),
            "- Vulnerability class: " + BugBountyReportService._code(finding.threat_class),
            (
                "- Affected component: "
                + BugBountyReportService._text(
                    finding.affected_component or "TODO: operator review"
                )
            ),
            f"- Confidence: {BugBountyReportService._code(f'{finding.confidence:.2f}')}",
            f"- PAJIN fingerprint: {BugBountyReportService._code(item.fingerprint)}",
            "",
            "## Summary",
            "",
            BugBountyReportService._text(finding.summary),
            "",
            "## Impact",
            "",
            BugBountyReportService._text(
                finding.impact or "TODO: describe demonstrated security and business impact."
            ),
            "",
            "## Root cause",
            "",
            BugBountyReportService._text(
                finding.root_cause or "TODO: confirm the root cause before submission."
            ),
            "",
            "## Reproduction",
            "",
        ]
        if finding.reproduction:
            lines.extend(
                f"{index}. {BugBountyReportService._text(step)}"
                for index, step in enumerate(finding.reproduction, start=1)
            )
        else:
            lines.append("1. TODO: add a minimum-impact reproduction.")
        lines.extend(["", "## Evidence", ""])
        if finding.evidence:
            lines.extend(f"- {BugBountyReportService._code(path)}" for path in finding.evidence)
        else:
            lines.append("- TODO: attach same-run evidence.")
        lines.extend(["", "## Remediation", ""])
        if finding.remediation:
            lines.extend(f"- {BugBountyReportService._text(item)}" for item in finding.remediation)
        else:
            lines.append("- TODO: add a remediation recommendation.")
        if item.duplicate_candidates:
            lines.extend(["", "## Duplicate review", ""])
            lines.append(
                "Review these candidates before submission: "
                + ", ".join(
                    BugBountyReportService._code(value) for value in item.duplicate_candidates
                )
            )
        if item.missing_fields:
            lines.extend(["", "## Required completion", ""])
            lines.extend(
                f"- {BugBountyReportService._code(value)}" for value in item.missing_fields
            )
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _code(value: str) -> str:
        return markdown_code_span(value)

    @staticmethod
    def _text(value: str) -> str:
        return escape_markdown_text(value)

    @staticmethod
    def _safe_finding_slug(finding_id: str) -> str:
        if fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", finding_id):
            return finding_id
        digest = sha256(finding_id.encode("utf-8")).hexdigest()[:24]
        return f"finding-{digest}"
