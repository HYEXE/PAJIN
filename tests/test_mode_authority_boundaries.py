import asyncio
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from pajin.domain.models import Finding, FindingSeverity, ToolResult
from pajin.domain.orchestration import RunStatus, TaskGraph, TaskNode, TaskStatus
from pajin.domain.validation import (
    CandidateFinding,
    FindingDisposition,
    FindingValidationSet,
    ValidationCheckResult,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
)
from pajin.modes.bug_bounty import (
    BugBountyFindingIndex,
    BugBountyProgramManifest,
    BugBountyReportService,
    BugBountyScopeApproval,
    BugBountyScopeService,
    load_bug_bounty_program,
)
from pajin.modes.ctf import (
    CTFChallengeManifest,
    CTFChallengeService,
    CTFModePack,
    CTFRunResult,
    CTFSolveStatus,
    CTFTriagePlannerRuntime,
    load_ctf_challenge,
)
from pajin.runtime.store import RunStore
from pajin.workflow.validation_artifacts import write_validation_artifacts


def _bug_bounty_approval(scope_digest: str) -> BugBountyScopeApproval:
    return BugBountyScopeApproval(
        scope_digest=scope_digest,
        approved_by="program-owner",
        approved_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
        expires_at=datetime(2099, 7, 13, 1, tzinfo=UTC),
        evidence="program-authorization",
    )


def _supported_semantic_checks() -> list[ValidationCheckResult]:
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


def test_bug_bounty_compile_rejects_mixed_concrete_generic_target() -> None:
    program = load_bug_bounty_program(Path("examples/bug-bounty-program.yaml"))
    payload = program.model_dump(mode="json", by_alias=True)
    payload["spec"]["scope"]["inScope"][0]["probeProfile"] = "boolean-sqli-lab"
    payload["spec"]["scope"]["inScope"][1]["entryPoints"] = [
        "https://owned.lab.example.invalid/health"
    ]
    mixed = BugBountyProgramManifest.model_validate(payload)
    service = BugBountyScopeService()
    review = service.review(mixed)

    with pytest.raises(ValueError, match=r"generic-http.*review-only"):
        service.compile_campaign(mixed, _bug_bounty_approval(review.scope_digest))


def test_bug_bounty_compile_rejects_stale_scope_approval() -> None:
    program = load_bug_bounty_program(Path("examples/bug-bounty-lab-program.yaml"))
    service = BugBountyScopeService()
    review = service.review(program)
    approval = _bug_bounty_approval(review.scope_digest).model_copy(
        update={"expires_at": datetime(2026, 7, 14, 1, tzinfo=UTC)}
    )

    with pytest.raises(ValueError, match="not active"):
        service.compile_campaign(
            program,
            approval,
            evaluated_at=datetime(2026, 7, 15, 1, tzinfo=UTC),
        )


def test_ineligible_bug_bounty_target_never_becomes_submission_ready(tmp_path: Path) -> None:
    program = load_bug_bounty_program(Path("examples/bug-bounty-lab-program.yaml"))
    service = BugBountyScopeService()
    review = service.review(program)
    campaign = service.compile_campaign(
        program,
        _bug_bounty_approval(review.scope_digest),
    )
    target = campaign.spec.targets[0].endpoint
    finding = Finding(
        finding_id="confirmed-ineligible-lab-finding",
        title="Synthetic SQL injection",
        severity=FindingSeverity.HIGH,
        threat_class="CWE-89",
        target=target,
        summary="The synthetic lookup expands a fixed boolean predicate.",
        impact="Only synthetic lab records are affected.",
        affected_component="synthetic lookup",
        root_cause="The lab concatenates its fixed identifier.",
        reproduction=["Run the fixed three-request comparison."],
        evidence=["evidence/finding.json"],
        remediation=["Use a parameterized lookup."],
        confidence=1.0,
        validated=True,
    )
    run_path = tmp_path / "run"
    (run_path / "evidence").mkdir(parents=True)
    store = RunStore("run_ineligible_bug_bounty", run_path)
    store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))
    candidate = CandidateFinding(
        candidate_id="candidate_ineligible_bug_bounty",
        claim=finding.model_copy(update={"validated": False}),
        source="legacy-validator-output",
        source_agent_id="agent:validator:ineligible",
        source_request_ids=["request_ineligible_bug_bounty"],
        created_at=datetime(2026, 7, 13, 2, 1, tzinfo=UTC),
    )
    decision = ValidationDecision(
        decision_id="decision_ineligible_bug_bounty",
        candidate_id=candidate.candidate_id,
        validator_id=candidate.source_agent_id,
        method=ValidationMethod.HYBRID_LEGACY_GATE,
        disposition=FindingDisposition.NEEDS_REVIEW,
        reason_codes=[ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING],
        decision_summary="Semantic review passed; independent reproduction is missing.",
        supporting_evidence=list(finding.evidence),
        contradicting_evidence=[],
        replay_request_ids=[],
        checks=_supported_semantic_checks(),
        decided_at=datetime(2026, 7, 13, 2, 2, tzinfo=UTC),
    )
    write_validation_artifacts(
        store,
        FindingValidationSet(
            candidates=[candidate],
            decisions=[decision],
            confirmed_findings=[],
        ),
    )
    store.write_json("findings.json", [])
    store.write_json("run.json", {"runId": store.run_id, "status": "completed"})
    store.write_json("evidence/finding.json", {"independentReplay": True})
    store.append_event(
        "campaign.started",
        {"campaign": campaign.metadata.name},
        occurred_at=datetime(2026, 7, 13, 2, tzinfo=UTC),
    )
    store.append_event(
        "campaign.completed",
        {"status": "completed"},
        occurred_at=datetime(2026, 7, 13, 3, tzinfo=UTC),
    )
    store.seal()

    artifacts = BugBountyReportService().report_run(
        program,
        run_path,
        known_findings=BugBountyFindingIndex(
            apiVersion="pajin.dev/v1alpha1",
            kind="BugBountyFindingIndex",
            programName=program.metadata.name,
            findings=[],
        ),
    )

    item = artifacts.report.items[0]
    assert artifacts.report.summary.ready == 0
    assert artifacts.report.summary.needs_review == 1
    assert not item.submission_eligible
    assert "target-not-bounty-eligible" in item.missing_fields


def test_ctf_finalizer_rejects_mutable_result_that_differs_from_sealed_evidence(
    tmp_path: Path,
) -> None:
    challenge = load_ctf_challenge(Path("examples/ctf-web-backup-lab.yaml"))
    campaign = CTFChallengeService().compile_campaign(challenge)
    plan = asyncio.run(CTFTriagePlannerRuntime().plan(campaign))
    request = plan.steps[0].request
    bound_request = request.model_copy(update={"agent_id": "agent:ctf-specialist"})
    graph = TaskGraph()
    graph.add(
        TaskNode(
            title="Execute the sealed CTF Specialist request",
            assigned_agent_id=bound_request.agent_id,
            request=bound_request,
            status=TaskStatus.SUCCEEDED,
            attempts=1,
        )
    )
    now = datetime.now(UTC)
    observed = ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=True,
        started_at=now,
        finished_at=now,
        data={
            "target": request.target,
            "challengeId": challenge.metadata.name,
            "scenarioId": challenge.spec.scenario,
            "status": 404,
            "discovered": False,
            "candidateFlag": None,
            "bodySha256": "0" * 64,
            "synthetic": True,
            "networkPerformed": True,
        },
    )
    run_path = tmp_path / "run"
    (run_path / "evidence").mkdir(parents=True)
    store = RunStore("run_ctf_stale_evidence", run_path)
    store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))
    store.write_json("plan.json", plan.model_dump(mode="json"))
    store.write_json("task-graph.json", graph.model_dump(mode="json"))
    store.write_json("run.json", {"runId": store.run_id, "status": "completed"})
    evidence = store.write_json(
        f"evidence/{request.request_id}.json",
        {
            "request": bound_request.model_dump(mode="json"),
            "policyDecision": {"allowed": True},
            "result": observed.model_dump(mode="json"),
        },
    )
    store.append_event("campaign.completed", {"status": "completed"})
    store.seal()

    forged = observed.model_copy(
        update={
            "data": {
                "target": request.target,
                "challengeId": challenge.metadata.name,
                "scenarioId": challenge.spec.scenario,
                "status": 200,
                "discovered": True,
                "candidateFlag": "PAJIN{fixed_web_backup_lab}",
                "bodySha256": "f" * 64,
                "synthetic": True,
                "networkPerformed": True,
            },
            "evidence": [evidence],
        }
    )
    outcome = SimpleNamespace(
        run_id=store.run_id,
        run_path=run_path,
        status=RunStatus.COMPLETED,
        plan=plan,
        tool_results=[forged],
    )

    with pytest.raises(ValueError, match="differ from sealed evidence"):
        CTFModePack().finalize(challenge, outcome)  # type: ignore[arg-type]


def test_mode_markdown_escapes_operator_controlled_html() -> None:
    program = load_bug_bounty_program(Path("examples/bug-bounty-program.yaml"))
    program_payload = program.model_dump(mode="json", by_alias=True)
    program_payload["metadata"]["displayName"] = "<img src=x onerror=alert(1)>"
    program_payload["metadata"]["platform"] = "`<img src=x onerror=alert(3)>"
    program = BugBountyProgramManifest.model_validate(program_payload)
    review = BugBountyScopeService().review(program)
    scope_markdown = BugBountyScopeService.render_review(program, review)

    challenge = load_ctf_challenge(Path("examples/ctf-web-backup-lab.yaml"))
    challenge_payload = challenge.model_dump(mode="json", by_alias=True)
    challenge_payload["metadata"]["displayName"] = "<img src=x onerror=alert(2)>"
    challenge = CTFChallengeManifest.model_validate(challenge_payload)
    ctf_markdown = CTFModePack._render_writeup(
        challenge,
        CTFRunResult(
            run_id="run_markdown_escape",
            challenge_id=challenge.metadata.name,
            category=challenge.spec.category,
            scenario=challenge.spec.scenario,
            status=CTFSolveStatus.UNSOLVED,
            expected_sha256=challenge.spec.flag.sha256,
            evidence=["evidence/`<img src=x onerror=alert(4)>.json"],
        ),
    )

    assert "<img" not in scope_markdown
    assert "&lt;img" in scope_markdown
    assert "`` `&lt;img src=x onerror=alert(3)&gt; ``" in scope_markdown
    assert "<img" not in ctf_markdown
    assert "&lt;img" in ctf_markdown
    assert "``evidence/`&lt;img src=x onerror=alert(4)&gt;.json``" in ctf_markdown
