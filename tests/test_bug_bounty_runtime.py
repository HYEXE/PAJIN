import asyncio
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
from typer.testing import CliRunner

import pajin.cli as cli
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
)
from pajin.domain.orchestration import RunStatus
from pajin.modes.bug_bounty import (
    BugBountyPlannerRuntime,
    BugBountyProgramManifest,
    BugBountyReportService,
    BugBountyScopeApproval,
    BugBountyScopeService,
    BugBountyValidatorRuntime,
    load_bug_bounty_program,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import RunStore
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import (
    BOOLEAN_SQLI_SCENARIO,
    BooleanSQLiProbeTool,
)
from pajin.tools.gateway import ToolGateway
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


def _program() -> BugBountyProgramManifest:
    return load_bug_bounty_program(Path("examples/bug-bounty-lab-program.yaml"))


def _campaign() -> CampaignManifest:
    program = _program()
    service = BugBountyScopeService()
    digest = service.review(program).scope_digest
    return service.compile_campaign(
        program,
        BugBountyScopeApproval(
            scope_digest=digest,
            approved_by="local-lab-owner",
            approved_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
            expires_at=datetime(2099, 7, 13, 1, tzinfo=UTC),
            evidence="local-lab-authorization",
        ),
    )


def _output(
    target: str,
    *,
    probe_status: int = 200,
    probe_count: int = 2,
    claimed_vulnerable: bool = False,
) -> dict[str, object]:
    return {
        "target": target,
        "scenarioId": BOOLEAN_SQLI_SCENARIO,
        "vulnerable": claimed_vulnerable,
        "checks": {
            "baselineSingleRecord": False,
            "negativeControlEmpty": False,
            "booleanProbeExpanded": False,
            "syntheticLabOnly": False,
        },
        "observations": [
            {"name": "baseline", "status": 200, "recordCount": 1, "synthetic": True},
            {
                "name": "negative-control",
                "status": 200,
                "recordCount": 0,
                "synthetic": True,
            },
            {
                "name": "boolean-probe",
                "status": probe_status,
                "recordCount": probe_count,
                "synthetic": True,
            },
        ],
        "networkPerformed": True,
    }


class ContractBugBountyWorker:
    def __init__(self, *, hardened: bool = False) -> None:
        self.hardened = hardened
        self.jobs: list[WorkerJob] = []

    async def run(self, job: WorkerJob) -> WorkerResult:
        self.jobs.append(job)
        assert job.command == ["bug-bounty-sqli-probe"]
        assert job.network is NetworkMode.EGRESS_PROXY
        assert job.egress_policy is not None
        assert job.egress_policy.allow_private_networks
        payload = json.loads(job.stdin)
        now = datetime.now(UTC)
        output = _output(
            payload["target"],
            probe_status=400 if self.hardened else 200,
            probe_count=0 if self.hardened else 2,
            claimed_vulnerable=not self.hardened,
        )
        return WorkerResult(
            execution_id=job.execution_id,
            backend="bug-bounty-contract-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=now,
            finished_at=now,
        )


class NeverWorker:
    async def run(self, job: WorkerJob) -> WorkerResult:
        raise AssertionError(f"denied probe reached Worker: {job.execution_id}")


def _worker_entry() -> ModuleType:
    path = Path("containers/worker/worker_entry.py")
    spec = importlib.util.spec_from_file_location("pajin_bug_bounty_worker_entry", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_boolean_sqli_tool_accepts_only_fixed_minimum_impact_contract() -> None:
    tool = BooleanSQLiProbeTool()
    target = "http://host.docker.internal:8770/v1/users/lookup"
    request = ToolRequest(
        agent_id="agent:specialist",
        tool_id=tool.spec.tool_id,
        target=target,
        method="GET",
        arguments={"scenario_id": BOOLEAN_SQLI_SCENARIO},
    )

    job = tool.prepare(request)

    assert tool.spec.network_request_cost == 3
    assert job.network is NetworkMode.NONE
    assert job.command == ["bug-bounty-sqli-probe"]
    assert json.loads(job.stdin) == {
        "target": target,
        "scenarioId": BOOLEAN_SQLI_SCENARIO,
    }
    assert " OR " not in job.stdin
    with pytest.raises(ValueError, match="requires GET"):
        tool.prepare(request.model_copy(update={"method": "POST"}))
    with pytest.raises(ValueError, match="query or fragment"):
        tool.prepare(request.model_copy(update={"target": f"{target}?id=1"}))
    with pytest.raises(ValueError, match="fixed to"):
        tool.prepare(request.model_copy(update={"target": "http://lab.invalid/admin"}))


def test_trusted_worker_owns_exactly_three_fixed_probe_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()
    captured: list[tuple[str, str]] = []

    def observe(target: str, value: str, name: str) -> dict[str, object]:
        del target
        captured.append((name, value))
        return {
            "name": name,
            "status": 200,
            "recordCount": 2 if name == "boolean-probe" else int(name == "baseline"),
            "synthetic": True,
        }

    monkeypatch.setattr(worker, "_get_bug_bounty_observation", observe)
    output = worker.bug_bounty_sqli_probe(
        {
            "target": "http://host.docker.internal:8770/v1/users/lookup",
            "scenarioId": BOOLEAN_SQLI_SCENARIO,
        }
    )

    assert captured == [
        ("baseline", "1"),
        ("negative-control", "1' AND '1'='2"),
        ("boolean-probe", "1' OR '1'='1"),
    ]
    assert output["vulnerable"] is True
    assert all("records" not in observation for observation in output["observations"])


def test_planner_emits_one_fixed_step_for_compiled_lab_target() -> None:
    campaign = _campaign()

    plan = asyncio.run(BugBountyPlannerRuntime().plan(campaign))

    assert len(plan.steps) == 1
    step = plan.steps[0]
    assert step.request.tool_id == "bug-bounty.boolean-sqli-probe"
    assert step.request.target == campaign.spec.targets[0].endpoint
    assert step.request.method == "GET"
    assert step.request.arguments == {"scenario_id": BOOLEAN_SQLI_SCENARIO}
    assert step.threat_classes == {"CWE-89"}


def test_validator_recomputes_observations_instead_of_trusting_claimed_checks() -> None:
    campaign = _campaign()
    plan = asyncio.run(BugBountyPlannerRuntime().plan(campaign))
    step = plan.steps[0]
    now = datetime.now(UTC)
    result = ToolResult(
        request_id=step.request.request_id,
        tool_id=step.request.tool_id,
        success=True,
        started_at=now,
        finished_at=now,
        data=_output(step.request.target, claimed_vulnerable=False),
        evidence=["evidence/probe.json"],
    )

    findings = asyncio.run(BugBountyValidatorRuntime().validate(campaign, plan, [result]))

    assert len(findings) == 1
    assert findings[0].validated
    assert findings[0].threat_class == "CWE-89"
    assert findings[0].root_cause
    assert findings[0].remediation

    hardened = result.model_copy(
        update={"data": _output(step.request.target, probe_status=400, probe_count=0)}
    )
    assert asyncio.run(BugBountyValidatorRuntime().validate(campaign, plan, [hardened])) == []


def test_gateway_reserves_all_three_http_request_units(tmp_path: Path) -> None:
    campaign = _campaign()
    rules = campaign.spec.rules_of_engagement.model_copy(update={"max_requests_per_minute": 2})
    campaign = campaign.model_copy(
        update={"spec": campaign.spec.model_copy(update={"rules_of_engagement": rules})}
    )
    target = campaign.spec.targets[0].endpoint
    tool = BooleanSQLiProbeTool()
    registry = ToolRegistry()
    registry.register(tool)
    request = ToolRequest(
        agent_id="agent:specialist",
        tool_id=tool.spec.tool_id,
        target=target,
        method="GET",
        arguments={"scenario_id": BOOLEAN_SQLI_SCENARIO},
    )
    grant = CapabilityGrant(
        subject=request.agent_id,
        campaign=campaign.metadata.name,
        tools={request.tool_id},
        targets={target},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=campaign.spec.authorization.expires_at,
    )
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=registry,
        worker=NeverWorker(),
        store=RunStore.create(tmp_path, campaign.metadata.name),
        clock=lambda: datetime(2026, 7, 13, 1, tzinfo=UTC),
    )

    outcome = asyncio.run(gateway.execute(campaign, grant, request, used_calls=0))

    assert not outcome.executed
    assert outcome.decision.policy == "rate-limit"
    assert "3 request units" in outcome.decision.reason


def test_multi_agent_run_creates_evidence_bound_ready_draft(tmp_path: Path) -> None:
    campaign = _campaign()
    worker = ContractBugBountyWorker()
    registry = ToolRegistry()
    registry.register(BooleanSQLiProbeTool())
    runner = MultiAgentCampaignRunner(
        planner=BugBountyPlannerRuntime(),
        validator=BugBountyValidatorRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))
    artifacts = BugBountyReportService().report_run(_program(), outcome.run_path)

    assert outcome.status is RunStatus.COMPLETED
    assert len(outcome.agents) == 5
    assert len(outcome.tool_results) == 1
    assert len(outcome.findings) == 1
    assert worker.jobs
    assert artifacts.report.summary.ready == 1
    assert artifacts.report.summary.needs_review == 0
    assert len(artifacts.submission_paths) == 1
    assert artifacts.submission_paths[0].is_file()
    assert "Vulnerability class" in outcome.report_path.read_text(encoding="utf-8")


def test_bug_bounty_run_cli_is_docker_only_and_never_submits_externally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program_path = Path("examples/bug-bounty-lab-program.yaml").resolve()
    program = _program()
    service = BugBountyScopeService()
    digest = service.review(program).scope_digest
    campaign_path = tmp_path / "campaign.yaml"
    service.write_campaign(
        program,
        BugBountyScopeApproval(
            scope_digest=digest,
            approved_by="local-lab-owner",
            approved_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
            expires_at=datetime(2099, 7, 13, 1, tzinfo=UTC),
            evidence="local-lab-authorization",
        ),
        campaign_path,
    )
    worker = ContractBugBountyWorker()
    requested_backends: list[str] = []

    def backend(name: str) -> ContractBugBountyWorker:
        requested_backends.append(name)
        return worker

    monkeypatch.setattr(cli, "_worker_backend", backend)
    result = CliRunner().invoke(
        cli.app,
        [
            "bug-bounty-run",
            str(program_path),
            str(campaign_path),
            "--output",
            str(tmp_path / "runs"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert requested_backends == ["docker"]
    assert "Ready drafts" in result.output
    assert "No external submission was performed." in result.output
