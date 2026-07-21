import asyncio
import importlib.util
import json
from base64 import b64decode, b64encode
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from urllib.parse import urlencode, urlsplit, urlunsplit

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
from pajin.domain.validation import FindingDisposition, ValidationReasonCode
from pajin.modes.bug_bounty import (
    BugBountyPlannerRuntime,
    BugBountyProgramManifest,
    BugBountyReportService,
    BugBountyScopeApproval,
    BugBountyScopeService,
    BugBountyValidationAuthority,
    BugBountyValidatorRuntime,
    load_bug_bounty_program,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.store import RunStore
from pajin.runtime.worker import (
    DockerWorkerBackend,
    NetworkMode,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import (
    EGRESS_HTTP_RECEIPT_VERSION,
    ToolRegistry,
    audit_http_target,
    http_target_sha256,
)
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
    def observation(name: str, status: int, record_count: int) -> dict[str, object]:
        body = json.dumps(
            {"recordCount": record_count, "synthetic": True},
            separators=(",", ":"),
        ).encode()
        return {
            "name": name,
            "status": status,
            "recordCount": record_count,
            "synthetic": True,
            "bodySha256": sha256(body).hexdigest(),
            "responseBodyBase64": b64encode(body).decode("ascii"),
        }

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
            observation("baseline", 200, 1),
            observation("negative-control", 200, 0),
            observation("boolean-probe", probe_status, probe_count),
        ],
        "networkPerformed": True,
    }


def _canonical_digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _proxy_receipt_log(job: WorkerJob, result: WorkerResult) -> str:
    payload = json.loads(job.stdin)
    output = json.loads(result.stdout)
    parsed = urlsplit(payload["target"])
    fixed_values = ("1", "1' AND '1'='2", "1' OR '1'='1")
    events = [json.dumps({"event": "ready", "port": 8080}, separators=(",", ":"))]
    for sequence, (value, observation) in enumerate(
        zip(fixed_values, output["observations"], strict=True),
        start=1,
    ):
        target = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode({"id": value}), "")
        )
        response_body = b64decode(observation["responseBodyBase64"], validate=True)
        response = json.loads(response_body)
        events.append(
            json.dumps(
                {
                    "event": "allow",
                    "receiptVersion": EGRESS_HTTP_RECEIPT_VERSION,
                    "sequence": sequence,
                    "method": "GET",
                    "target": audit_http_target(target),
                    "targetSha256": http_target_sha256(target),
                    "address": "172.17.0.1",
                    "status": observation["status"],
                    "responseBodySha256": sha256(response_body).hexdigest(),
                    "responseJsonSha256": _canonical_digest(response),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(events)


def _trusted_docker_backend(
    worker: "ContractBugBountyWorker",
    *,
    forge_body_digest: bool = False,
    forge_record_count: bool = False,
    forge_target_digest: bool = False,
) -> DockerWorkerBackend:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})

    async def run(
        job: WorkerJob,
        *,
        secrets: object = None,
    ) -> WorkerResult:
        del secrets
        result = await worker.run(job)
        network_log = _proxy_receipt_log(job, result)
        if forge_target_digest:
            events = network_log.splitlines()
            receipt = json.loads(events[1])
            receipt["targetSha256"] = "0" * 64
            events[1] = json.dumps(receipt, separators=(",", ":"))
            network_log = "\n".join(events)
        if forge_body_digest:
            output = json.loads(result.stdout)
            output["observations"][0]["bodySha256"] = "f" * 64
            result = result.model_copy(update={"stdout": json.dumps(output)})
        if forge_record_count:
            output = json.loads(result.stdout)
            output["observations"][2]["recordCount"] = 99
            result = result.model_copy(update={"stdout": json.dumps(output)})
        return result.model_copy(update={"backend": "docker", "network_log": network_log})

    backend.run = run  # type: ignore[method-assign]
    return backend


class ContractBugBountyWorker:
    def __init__(self, *, hardened: bool = False) -> None:
        self.hardened = hardened
        self.jobs: list[WorkerJob] = []

    def stable_execution_context(self) -> dict[str, object]:
        return {
            "implementationVersion": "test.contract-bug-bounty-worker/v1",
            "hardened": self.hardened,
        }

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del secrets
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
    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "test.never-worker/v1"}

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del secrets
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
            "bodySha256": "0" * 64,
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
        issued_at=campaign.spec.authorization.approved_at,
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


def test_multi_agent_run_creates_review_only_draft_for_semantic_candidate(
    tmp_path: Path,
) -> None:
    campaign = _campaign()
    worker = ContractBugBountyWorker()
    registry = ToolRegistry()
    registry.register(BooleanSQLiProbeTool())
    runner = MultiAgentCampaignRunner(
        planner=BugBountyPlannerRuntime(),
        validator=BugBountyValidatorRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=_trusted_docker_backend(worker),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))
    artifacts = BugBountyReportService().report_run(_program(), outcome.run_path)

    assert outcome.status is RunStatus.COMPLETED
    assert len(outcome.agents) == 5
    assert len(outcome.tool_results) == 1
    assert outcome.findings == []
    assert len(outcome.validation.candidates) == 1
    assert outcome.validation.decisions[0].disposition is FindingDisposition.NEEDS_REVIEW
    assert outcome.validation.decisions[0].reason_codes == [
        ValidationReasonCode.INDEPENDENT_REPRODUCTION_MISSING
    ]
    assert worker.jobs
    assert artifacts.report.summary.ready == 0
    assert artifacts.report.summary.needs_review == 1
    assert len(artifacts.submission_paths) == 1
    item = artifacts.report.items[0]
    assert item.validation_authority is BugBountyValidationAuthority.SEMANTIC_REVIEW_ONLY
    assert not item.finding.validated
    assert not item.submission_eligible
    assert "independent-reproduction-not-confirmed" in item.missing_fields
    draft = artifacts.submission_paths[0].read_text(encoding="utf-8")
    assert "Review-only Candidate" in draft
    assert "not submission-eligible" in draft
    assert "Needs review: `1`" in outcome.report_path.read_text(encoding="utf-8")


def test_hardened_bug_bounty_run_has_no_candidate_or_draft(tmp_path: Path) -> None:
    campaign = _campaign()
    worker = ContractBugBountyWorker(hardened=True)
    registry = ToolRegistry()
    registry.register(BooleanSQLiProbeTool())
    runner = MultiAgentCampaignRunner(
        planner=BugBountyPlannerRuntime(),
        validator=BugBountyValidatorRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=_trusted_docker_backend(worker),
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))
    artifacts = BugBountyReportService().report_run(_program(), outcome.run_path)

    assert outcome.status is RunStatus.COMPLETED
    assert outcome.validation.candidates == []
    assert outcome.validation.decisions == []
    assert outcome.findings == []
    assert artifacts.report.summary.total == 0
    assert artifacts.submission_paths == []


@pytest.mark.parametrize(
    "forgery",
    ["untrusted", "body-digest", "record-count", "target-digest"],
)
def test_bug_bounty_worker_claim_cannot_succeed_without_matching_host_receipts(
    tmp_path: Path,
    forgery: str,
) -> None:
    campaign = _campaign()
    worker = ContractBugBountyWorker()
    registry = ToolRegistry()
    registry.register(BooleanSQLiProbeTool())
    backend: DockerWorkerBackend | ContractBugBountyWorker
    if forgery == "body-digest":
        backend = _trusted_docker_backend(worker, forge_body_digest=True)
    elif forgery == "record-count":
        backend = _trusted_docker_backend(worker, forge_record_count=True)
    elif forgery == "target-digest":
        backend = _trusted_docker_backend(worker, forge_target_digest=True)
    else:
        backend = worker
    runner = MultiAgentCampaignRunner(
        planner=BugBountyPlannerRuntime(),
        validator=BugBountyValidatorRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=backend,
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))

    assert outcome.status is RunStatus.FAILED
    assert len(outcome.tool_results) == 1
    assert not outcome.tool_results[0].success
    assert outcome.findings == []
    assert outcome.validation.candidates == []


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

    trusted_worker = _trusted_docker_backend(worker)

    def backend(name: str) -> DockerWorkerBackend:
        requested_backends.append(name)
        return trusted_worker

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
    assert "Candidate needs review" in result.output
    assert "Submission drafts: 1" in result.output
    assert "No external submission was performed." in result.output
