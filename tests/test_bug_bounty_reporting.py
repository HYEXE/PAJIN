import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.domain.models import CampaignManifest, Finding, FindingSeverity
from pajin.modes.bug_bounty import (
    BugBountyFindingIndex,
    BugBountyProgramManifest,
    BugBountyReportService,
    BugBountyScopeApproval,
    BugBountyScopeService,
    DuplicateDisposition,
    KnownBugBountyFinding,
    KnownFindingStatus,
    load_bug_bounty_finding_index,
    load_bug_bounty_program,
)
from pajin.runtime.store import RunStore, verify_run_integrity


def _program() -> BugBountyProgramManifest:
    program = load_bug_bounty_program(Path("examples/bug-bounty-program.yaml"))
    payload = program.model_dump(mode="json", by_alias=True)
    payload["spec"]["scope"]["inScope"][0]["entryPoints"].append(
        "https://api.example.invalid/v1/profile"
    )
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
    target: str = "https://api.example.invalid/v1/health",
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
) -> Path:
    run_path = tmp_path / f"run-{len(list(tmp_path.glob('run-*')))}"
    (run_path / "evidence").mkdir(parents=True)
    store = RunStore(run_id="run_bug_bounty_test", path=run_path)
    store.write_json(
        "campaign.json",
        _campaign(program).model_dump(mode="json", by_alias=True),
    )
    store.write_json("findings.json", [finding.model_dump(mode="json") for finding in findings])
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
    store.seal()
    return run_path


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
        target="https://api.example.invalid/v1/profile",
    )
    run_path = _run(tmp_path, program, [first, second])

    artifacts = BugBountyReportService().report_run(program, run_path)

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
        title="<script>alert('report')</script>",
    )
    run_path = _run(tmp_path, program, [finding])

    artifacts = BugBountyReportService().report_run(program, run_path)
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
    assert "TODO: confirm the root cause" in draft
    assert artifacts.submission_paths[0].parent.name == "submissions"
    assert artifacts.submission_paths[0].name.startswith("finding-")


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
    assert verify_run_integrity(run_path).seal_count == 2

    with pytest.raises(ValueError, match="already exists"):
        BugBountyReportService().report_run(
            program,
            run_path,
            known_findings=load_bug_bounty_finding_index(index_path),
        )
