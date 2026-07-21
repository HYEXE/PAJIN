import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

import pajin.workflow.validation_artifacts as validation_artifacts
from pajin.domain.models import CampaignManifest, Finding, FindingSeverity
from pajin.domain.validation import (
    CandidateFinding,
    ConfirmationBasis,
    FindingDisposition,
    FindingValidationSet,
    ReplayConfirmationLineage,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
    VersionedConfirmedFindingSet,
    VersionedValidationDecisionSet,
    VersionedValidationIndex,
)
from pajin.modes.bug_bounty import (
    BugBountyFindingIndex,
    BugBountyProgramManifest,
    BugBountyReportService,
    BugBountyScopeApproval,
    BugBountyScopeService,
    BugBountyValidationAuthority,
    DuplicateDisposition,
    KnownBugBountyFinding,
    KnownFindingStatus,
    load_bug_bounty_finding_index,
    load_bug_bounty_program,
)
from pajin.runtime.store import RunStore, load_verified_run_snapshot, verify_run_integrity
from pajin.workflow.validation_artifacts import (
    VERSIONED_VALIDATION_DECISIONS_PATH,
    VERSIONED_VALIDATION_FINDINGS_PATH,
    VERSIONED_VALIDATION_INDEX_PATH,
    VERSIONED_VALIDATION_REPORT_PATH,
    write_validation_artifacts,
)


def _program() -> BugBountyProgramManifest:
    program = load_bug_bounty_program(Path("examples/bug-bounty-program.yaml"))
    payload = program.model_dump(mode="json", by_alias=True)
    payload["spec"]["scope"]["inScope"][0]["probeProfile"] = "boolean-sqli-lab"
    payload["spec"]["scope"]["inScope"][0]["entryPoints"] = [
        "https://api.example.invalid/v1/users/lookup",
        "https://api.example.invalid/v1/profile/users/lookup",
    ]
    return BugBountyProgramManifest.model_validate(payload)


def _campaign(program: BugBountyProgramManifest) -> CampaignManifest:
    service = BugBountyScopeService()
    digest = service.review(program).scope_digest
    return service.compile_campaign(
        program,
        BugBountyScopeApproval(
            scope_digest=digest,
            approved_by="program-owner",
            approved_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
            expires_at=datetime(2027, 7, 13, 1, tzinfo=UTC),
            evidence="program-ticket-123",
        ),
    )


def _finding(
    finding_id: str,
    *,
    target: str = "https://api.example.invalid/v1/users/lookup",
    confidence: float = 0.95,
    root_cause: str | None = "Untrusted input is concatenated into a SQL query.",
    component: str | None = "user lookup query",
    impact: str | None = "An attacker can read synthetic account records from the lab.",
    remediation: list[str] | None = None,
    validated: bool = True,
    evidence: list[str] | None = None,
    title: str = "SQL injection in user lookup",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=title,
        severity=FindingSeverity.HIGH,
        threat_class="CWE-89",
        target=target,
        summary="The user lookup accepts an injectable identifier.",
        impact=impact,
        affected_component=component,
        root_cause=root_cause,
        reproduction=["Send the minimum-impact boolean probe.", "Compare the response."],
        evidence=evidence if evidence is not None else [f"evidence/{finding_id}.json"],
        remediation=(
            remediation
            if remediation is not None
            else ["Use parameterized queries and validate the identifier type."]
        ),
        confidence=confidence,
        validated=validated,
    )


def _run(
    tmp_path: Path,
    program: BugBountyProgramManifest,
    findings: list[Finding],
    *,
    write_evidence: bool = True,
    independently_replayed: bool = True,
    forge_source_authority: bool = False,
) -> Path:
    run_path = tmp_path / f"run-{len(list(tmp_path.glob('run-*')))}"
    (run_path / "evidence").mkdir(parents=True)
    store = RunStore(run_id="run_bug_bounty_test", path=run_path)
    store.write_json(
        "campaign.json",
        _campaign(program).model_dump(mode="json", by_alias=True),
    )
    store.write_json("run.json", {"runId": store.run_id, "status": "completed"})
    if write_evidence:
        for finding in findings:
            for evidence in finding.evidence:
                if evidence.startswith("evidence/"):
                    store.write_json(evidence, {"findingId": finding.finding_id})
    store.append_event(
        "campaign.started",
        {"campaign": program.metadata.name, "mode": "bug-bounty"},
        occurred_at=datetime(2026, 7, 13, 1, 30, tzinfo=UTC),
    )
    store.append_event(
        "campaign.completed",
        {"status": "completed", "report": "report.md"},
        occurred_at=datetime(2026, 7, 13, 1, 31, tzinfo=UTC),
    )
    candidates: list[CandidateFinding] = []
    source_decisions: list[ValidationDecision] = []
    for ordinal, finding in enumerate(findings, start=1):
        candidate_id = f"candidate_bug_bounty_{ordinal}"
        validator_id = f"agent:validator:{ordinal}"
        candidates.append(
            CandidateFinding(
                candidate_id=candidate_id,
                claim=finding.model_copy(update={"validated": False}),
                source="legacy-validator-output",
                source_agent_id=("agent:forged" if forge_source_authority else validator_id),
                source_request_ids=[f"request_source_{ordinal}"],
                created_at=datetime(2026, 7, 13, 1, 32, tzinfo=UTC),
            )
        )
        source_decisions.append(
            ValidationDecision(
                decision_id=f"decision_source_{ordinal}",
                candidate_id=candidate_id,
                validator_id=validator_id,
                method=ValidationMethod.HYBRID_LEGACY_GATE,
                disposition=FindingDisposition.NEEDS_REVIEW,
                reason_codes=[ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING],
                decision_summary=(
                    "Semantic validation supported the exact claim; independent replay is "
                    "still required."
                ),
                supporting_evidence=list(finding.evidence),
                contradicting_evidence=[],
                replay_request_ids=[],
                checks=_semantic_review_checks(),
                decided_at=datetime(2026, 7, 13, 1, 33, tzinfo=UTC),
            )
        )
    source_validation = FindingValidationSet(
        candidates=candidates,
        decisions=source_decisions,
        confirmed_findings=[],
    )
    write_validation_artifacts(store, source_validation)
    store.write_json("findings.json", [])
    source_seal = store.seal()
    if independently_replayed and findings:
        _write_independent_projection(
            store,
            candidates=candidates,
            source_decisions=source_decisions,
            source_root_digest=source_seal.root_digest,
        )
    return run_path


def _semantic_review_checks() -> list[ValidationCheckResult]:
    checks = [
        ValidationCheckResult(
            check_id=check_id,
            status=ValidationCheckStatus.PASS,
            summary="The exact sealed validation prerequisite passed.",
        )
        for check_id in (
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
        )
    ]
    checks.extend(
        [
            ValidationCheckResult(
                check_id="legacy-validator-signal",
                status=ValidationCheckStatus.PASS,
                reason_code=ValidationReasonCode.VALIDATOR_CONFIRMED,
                summary="The Validator supported the exact Candidate claim.",
            ),
            ValidationCheckResult(
                check_id="independent-reproduction",
                status=ValidationCheckStatus.FAIL,
                reason_code=ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING,
                summary="Independent reproduction has not run.",
            ),
        ]
    )
    return checks


def _write_independent_projection(
    store: RunStore,
    *,
    candidates: list[CandidateFinding],
    source_decisions: list[ValidationDecision],
    source_root_digest: str,
) -> None:
    final_decisions: list[ValidationDecision] = []
    confirmed_findings: list[Finding] = []
    for ordinal, (candidate, source_decision) in enumerate(
        zip(candidates, source_decisions, strict=True),
        start=1,
    ):
        lineage = ReplayConfirmationLineage(
            replay_run_id=f"run_replay_{ordinal}",
            replay_outcome_id=f"outcome_replay_{ordinal}",
            replay_request_ids=[f"request_replay_{ordinal}"],
            replay_evidence=[],
            oracle_result_id=f"oracle_replay_{ordinal}",
            ticket_id=f"ticket_replay_{ordinal}",
            candidate_source_root_digest=source_root_digest,
            artifact_set_digest=f"{ordinal:x}".rjust(64, "0"),
            artifact_seal_root_digest=f"{ordinal + 100:x}".rjust(64, "0"),
            receipt_seal_root_digest=f"{ordinal + 200:x}".rjust(64, "0"),
            verified_at=datetime(2026, 7, 13, 1, 34, tzinfo=UTC),
        )
        final_decisions.append(
            ValidationDecision(
                decision_id=f"decision_replay_{ordinal}",
                supersedes_decision_id=source_decision.decision_id,
                candidate_id=candidate.candidate_id,
                validator_id="trusted-core:confirmed-gate",
                method=ValidationMethod.RESTRICTED_REPLAY_GATE,
                disposition=FindingDisposition.CONFIRMED,
                confirmation_basis=ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY,
                reason_codes=[ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED],
                decision_summary="Verified independent replay supported the exact claim.",
                supporting_evidence=source_decision.supporting_evidence,
                contradicting_evidence=[],
                replay_request_ids=lineage.replay_request_ids,
                replay_outcome_ids=[lineage.replay_outcome_id],
                replay_lineage=[lineage],
                checks=[],
                decided_at=datetime(2026, 7, 13, 1, 35, tzinfo=UTC),
            )
        )
        confirmed_findings.append(candidate.claim.model_copy(update={"validated": True}))

    index = VersionedValidationIndex(
        sourceRunId=store.run_id,
        candidateSourceRootDigest=source_root_digest,
        confirmationSemantics="verified-independent-replay",
        dispositions={
            FindingDisposition.CONFIRMED: [candidate.candidate_id for candidate in candidates],
            FindingDisposition.NEEDS_REVIEW: [],
            FindingDisposition.INCONCLUSIVE: [],
            FindingDisposition.REJECTED_OBJECTIVE: [],
        },
        confirmedCandidateIds=[candidate.candidate_id for candidate in candidates],
        generatedAt=datetime(2026, 7, 13, 1, 35, tzinfo=UTC),
    )
    store.write_json(
        VERSIONED_VALIDATION_DECISIONS_PATH,
        VersionedValidationDecisionSet(
            sourceRunId=store.run_id,
            decisions=final_decisions,
        ).model_dump(mode="json", by_alias=True),
    )
    store.write_json(
        VERSIONED_VALIDATION_FINDINGS_PATH,
        VersionedConfirmedFindingSet(
            sourceRunId=store.run_id,
            confirmationSemantics="verified-independent-replay",
            findings=confirmed_findings,
        ).model_dump(mode="json", by_alias=True),
    )
    store.write_text(VERSIONED_VALIDATION_REPORT_PATH, "# Verified replay projection\n")
    store.write_json(
        VERSIONED_VALIDATION_INDEX_PATH,
        index.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "validation.confirmation-projection.created",
        {"index": VERSIONED_VALIDATION_INDEX_PATH},
    )
    store.seal()


def _known_index(
    program: BugBountyProgramManifest,
    finding: Finding,
    *,
    status: KnownFindingStatus,
) -> BugBountyFindingIndex:
    assert finding.affected_component is not None
    assert finding.root_cause is not None
    return BugBountyFindingIndex(
        apiVersion="pajin.dev/v1alpha1",
        kind="BugBountyFindingIndex",
        programName=program.metadata.name,
        findings=[
            KnownBugBountyFinding(
                externalId="BB-1042",
                target=finding.target,
                vulnerabilityClass=finding.threat_class,
                affectedComponent=finding.affected_component,
                rootCause=finding.root_cause,
                status=status,
                reference="https://security.example.invalid/reports/BB-1042",
            )
        ],
    )


def _empty_known_index(program: BugBountyProgramManifest) -> BugBountyFindingIndex:
    return BugBountyFindingIndex(
        apiVersion="pajin.dev/v1alpha1",
        kind="BugBountyFindingIndex",
        programName=program.metadata.name,
        findings=[],
    )


def test_bug_bounty_report_rejects_validation_from_an_intermediate_run_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = _program()
    run_path = _run(tmp_path, program, [_finding("finding-phase-bound")])
    authority = load_verified_run_snapshot(run_path)
    phase_b_verification = authority.verification.model_copy(update={"root_digest": "0" * 64})
    original_artifact_load = validation_artifacts.load_verified_run_artifacts
    phase_b_initial_loads = 0

    def phase_b_initial(*args, **kwargs):
        nonlocal phase_b_initial_loads
        phase_b_initial_loads += 1
        return replace(authority, verification=phase_b_verification)

    def phase_b_artifacts(*args, **kwargs):
        snapshot = original_artifact_load(*args, **kwargs)
        return replace(snapshot, verification=phase_b_verification)

    monkeypatch.setattr(
        validation_artifacts,
        "load_verified_run_snapshot",
        phase_b_initial,
    )
    monkeypatch.setattr(
        validation_artifacts,
        "load_verified_run_artifacts",
        phase_b_artifacts,
    )

    with pytest.raises(ValueError, match="validation Run changed"):
        BugBountyReportService().report_run(program, run_path)
    assert phase_b_initial_loads == 0
    assert not (run_path / "bug-bounty-reports").exists()


def test_exact_same_run_fingerprint_suppresses_only_lower_priority_duplicate(
    tmp_path: Path,
) -> None:
    program = _program()
    primary = _finding("finding-primary", confidence=0.99)
    duplicate = _finding("finding-duplicate", confidence=0.80)
    run_path = _run(tmp_path, program, [duplicate, primary])

    artifacts = BugBountyReportService().report_run(
        program,
        run_path,
        known_findings=_empty_known_index(program),
        generated_at=datetime(2026, 7, 13, 2, tzinfo=UTC),
    )

    dispositions = {item.finding.finding_id: item.disposition for item in artifacts.report.items}
    assert dispositions == {
        "finding-primary": DuplicateDisposition.READY,
        "finding-duplicate": DuplicateDisposition.RUN_DUPLICATE,
    }
    assert artifacts.report.summary.ready == 1
    assert artifacts.report.summary.run_duplicates == 1
    assert len(artifacts.submission_paths) == 1


def test_same_root_cause_on_different_endpoint_requires_review_for_both(
    tmp_path: Path,
) -> None:
    program = _program()
    first = _finding("finding-health")
    second = _finding(
        "finding-profile",
        target="https://api.example.invalid/v1/profile/users/lookup",
    )
    run_path = _run(tmp_path, program, [first, second])

    artifacts = BugBountyReportService().report_run(
        program,
        run_path,
        known_findings=_empty_known_index(program),
    )

    assert artifacts.report.summary.needs_review == 2
    assert all(
        item.disposition is DuplicateDisposition.NEEDS_REVIEW for item in artifacts.report.items
    )
    assert all(item.duplicate_candidates for item in artifacts.report.items)
    assert len(artifacts.submission_paths) == 2


def test_unresolved_known_exact_match_is_suppressed_but_resolved_match_is_reviewed(
    tmp_path: Path,
) -> None:
    program = _program()
    finding = _finding("finding-known")
    open_run = _run(tmp_path, program, [finding])
    open_artifacts = BugBountyReportService().report_run(
        program,
        open_run,
        known_findings=_known_index(program, finding, status=KnownFindingStatus.OPEN),
    )
    assert open_artifacts.report.items[0].disposition is DuplicateDisposition.KNOWN_DUPLICATE
    assert not open_artifacts.submission_paths

    resolved_run = _run(tmp_path, program, [finding])
    resolved_artifacts = BugBountyReportService().report_run(
        program,
        resolved_run,
        known_findings=_known_index(program, finding, status=KnownFindingStatus.RESOLVED),
    )
    item = resolved_artifacts.report.items[0]
    assert item.disposition is DuplicateDisposition.NEEDS_REVIEW
    assert item.duplicate_candidates == ["BB-1042"]
    assert len(resolved_artifacts.submission_paths) == 1


def test_incomplete_finding_emits_escaped_needs_review_draft(tmp_path: Path) -> None:
    program = _program()
    finding = _finding(
        "../../unsafe-finding-id",
        root_cause=None,
        component=None,
        impact=None,
        remediation=[],
        evidence=["evidence/safe-incomplete.json"],
        title="<script>alert('report')</script>\n## forged heading",
    )
    run_path = _run(tmp_path, program, [finding])

    artifacts = BugBountyReportService().report_run(
        program,
        run_path,
        known_findings=_empty_known_index(program),
    )
    item = artifacts.report.items[0]
    draft = artifacts.submission_paths[0].read_text(encoding="utf-8")

    assert item.disposition is DuplicateDisposition.NEEDS_REVIEW
    assert {
        "impact",
        "remediation",
        "dedup-affected-component",
        "dedup-root-cause",
    } <= set(item.missing_fields)
    assert "&lt;script&gt;" in draft
    assert "\n## forged heading" not in draft
    assert "\\#\\# forged heading" in draft
    assert "TODO: confirm the root cause" in draft
    assert artifacts.submission_paths[0].parent.name == "submissions"
    assert artifacts.submission_paths[0].name.startswith("finding-")


def test_required_duplicate_check_without_an_index_never_marks_a_finding_ready(
    tmp_path: Path,
) -> None:
    program = _program()
    run_path = _run(tmp_path, program, [_finding("finding-unchecked")])

    artifacts = BugBountyReportService().report_run(program, run_path)

    item = artifacts.report.items[0]
    assert item.disposition is DuplicateDisposition.NEEDS_REVIEW
    assert not item.submission_eligible
    assert item.missing_fields == ["duplicate-check-not-performed"]
    assert artifacts.report.summary.ready == 0
    assert artifacts.report.summary.needs_review == 1


def test_report_code_spans_cannot_be_closed_by_untrusted_backticks(tmp_path: Path) -> None:
    program = _program()
    finding = _finding(
        "finding-`-code",
        evidence=["evidence/safe-code-span.json"],
    )
    run_path = _run(tmp_path, program, [finding])

    artifacts = BugBountyReportService().report_run(
        program,
        run_path,
        known_findings=_empty_known_index(program),
    )
    report = artifacts.report_path.read_text(encoding="utf-8")

    assert "- Finding ID: ``finding-`-code``" in report
    assert "- Finding ID: `finding-\\`-code`" not in report


def test_semantic_candidate_creates_only_an_escaped_review_draft(tmp_path: Path) -> None:
    program = _program()
    finding = _finding(
        "finding-semantic-review",
        title="<script>alert('candidate')</script>\n## forged review heading",
    )
    run_path = _run(
        tmp_path,
        program,
        [finding],
        independently_replayed=False,
    )

    artifacts = BugBountyReportService().report_run(
        program,
        run_path,
        known_findings=_empty_known_index(program),
    )

    item = artifacts.report.items[0]
    draft = artifacts.submission_paths[0].read_text(encoding="utf-8")
    assert artifacts.report.summary.ready == 0
    assert artifacts.report.summary.needs_review == 1
    assert item.validation_authority is BugBountyValidationAuthority.SEMANTIC_REVIEW_ONLY
    assert not item.finding.validated
    assert not item.submission_eligible
    assert item.missing_fields == ["independent-reproduction-not-confirmed"]
    assert "&lt;script&gt;" in draft
    assert "\n## forged review heading" not in draft
    assert "\\#\\# forged review heading" in draft
    assert "Review-only Candidate" in draft


def test_semantic_candidate_with_forged_source_authority_fails_closed(
    tmp_path: Path,
) -> None:
    program = _program()
    run_path = _run(
        tmp_path,
        program,
        [_finding("finding-forged-authority")],
        independently_replayed=False,
        forge_source_authority=True,
    )

    with pytest.raises(ValueError, match="invalid source authority"):
        BugBountyReportService().report_run(
            program,
            run_path,
            known_findings=_empty_known_index(program),
        )


def test_report_rejects_stale_policy_tampered_campaign_and_invalid_evidence(
    tmp_path: Path,
) -> None:
    program = _program()
    finding = _finding("finding-safe")
    stale_run = _run(tmp_path, program, [finding])
    changed = program.model_copy(deep=True)
    changed.spec.policy.raw_text += "\nNew restriction published after this run."
    with pytest.raises(ValueError, match="current program policy digest"):
        BugBountyReportService().report_run(changed, stale_run)

    tampered_run = _run(tmp_path, program, [finding])
    campaign_path = tampered_run / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    campaign["spec"]["rulesOfEngagement"]["maxRequestsPerMinute"] = 500
    campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
    with pytest.raises(ValueError, match="sealed Run artifact changed"):
        BugBountyReportService().report_run(program, tampered_run)

    missing_evidence = _finding(
        "finding-missing-evidence",
        evidence=["evidence/not-created.json"],
    )
    evidence_run = _run(
        tmp_path,
        program,
        [missing_evidence],
        write_evidence=False,
    )
    with pytest.raises(ValueError, match="missing or outside"):
        BugBountyReportService().report_run(program, evidence_run)


def test_report_writes_structured_artifacts_event_and_loads_known_index(
    tmp_path: Path,
) -> None:
    program = _program()
    finding = _finding("finding-artifact")
    run_path = _run(tmp_path, program, [finding])
    index_path = tmp_path / "known-findings.yaml"
    index_path.write_text(
        "\n".join(
            [
                "apiVersion: pajin.dev/v1alpha1",
                "kind: BugBountyFindingIndex",
                f"programName: {program.metadata.name}",
                "findings: []",
                "",
            ]
        ),
        encoding="utf-8",
    )

    artifacts = BugBountyReportService().report_run(
        program,
        run_path,
        known_findings=load_bug_bounty_finding_index(index_path),
    )

    triage = json.loads(artifacts.triage_path.read_text(encoding="utf-8"))
    assert triage["summary"]["ready"] == 1
    assert artifacts.report_path.is_file()
    assert artifacts.submission_paths[0].is_file()
    events = (run_path / "events.jsonl").read_text(encoding="utf-8")
    assert '"event_type":"mode-pack.bug-bounty.reported"' in events
    assert verify_run_integrity(run_path).seal_count == 3

    with pytest.raises(ValueError, match="already exists"):
        BugBountyReportService().report_run(
            program,
            run_path,
            known_findings=load_bug_bounty_finding_index(index_path),
        )
