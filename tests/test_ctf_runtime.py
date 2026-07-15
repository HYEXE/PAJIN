import asyncio
import importlib.util
import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from typer.testing import CliRunner

import pajin.cli as cli
from pajin.domain.models import ToolRequest
from pajin.domain.orchestration import RunStatus
from pajin.modes.ctf import (
    CTFChallengeManifest,
    CTFChallengeService,
    CTFFlagValidatorRuntime,
    CTFModePack,
    CTFSolveStatus,
    CTFTriagePlannerRuntime,
    load_ctf_challenge,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import ToolRegistry
from pajin.tools.ctf import CTF_WEB_BACKUP_TOOL_ID, CTFWebBackupProbeTool
from pajin.workflow.multi_agent import MultiAgentCampaignRunner, MultiAgentRunOutcome

FLAG = "PAJIN{fixed_web_backup_lab}"


def _challenge() -> CTFChallengeManifest:
    return load_ctf_challenge(Path("examples/ctf-web-backup-lab.yaml"))


class ContractCTFWorker:
    def __init__(self, candidate: str | None = FLAG) -> None:
        self.candidate = candidate
        self.jobs: list[WorkerJob] = []

    async def run(self, job: WorkerJob) -> WorkerResult:
        self.jobs.append(job)
        assert job.command == ["ctf-web-backup-probe"]
        assert job.network is NetworkMode.EGRESS_PROXY
        assert job.egress_policy is not None
        assert job.egress_policy.allow_private_networks
        payload = json.loads(job.stdin)
        now = datetime.now(UTC)
        output = {
            "target": payload["target"],
            "challengeId": payload["challengeId"],
            "scenarioId": payload["scenarioId"],
            "status": 200 if self.candidate is not None else 404,
            "discovered": self.candidate is not None,
            "candidateFlag": self.candidate,
            "bodySha256": "0" * 64,
            "synthetic": True,
            "networkPerformed": True,
        }
        return WorkerResult(
            execution_id=job.execution_id,
            backend="ctf-contract-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=now,
            finished_at=now,
        )


def _run(tmp_path: Path, candidate: str | None = FLAG) -> tuple[MultiAgentRunOutcome, CTFModePack]:
    registry = ToolRegistry()
    registry.register(CTFWebBackupProbeTool())
    runner = MultiAgentCampaignRunner(
        planner=CTFTriagePlannerRuntime(),
        validator=CTFFlagValidatorRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=ContractCTFWorker(candidate),
        output_root=tmp_path,
    )
    challenge = _challenge()
    campaign = CTFChallengeService().compile_campaign(challenge)
    return asyncio.run(runner.run(campaign)), CTFModePack()


def _worker_entry() -> ModuleType:
    path = Path("containers/worker/worker_entry.py")
    spec = importlib.util.spec_from_file_location("pajin_ctf_worker_entry", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ctf_web_tool_accepts_only_the_fixed_local_contract() -> None:
    target = "http://host.docker.internal:8780/backup/config.json.bak"
    request = ToolRequest(
        agent_id="agent:ctf-web-specialist",
        tool_id=CTF_WEB_BACKUP_TOOL_ID,
        target=target,
        method="GET",
        arguments={
            "challengeId": "web-backup-lab",
            "scenarioId": "web.exposed-backup-config",
        },
    )
    tool = CTFWebBackupProbeTool()

    job = tool.prepare(request)

    assert tool.spec.network_request_cost == 1
    assert job.network is NetworkMode.NONE
    assert job.command == ["ctf-web-backup-probe"]
    payload = json.loads(job.stdin)
    assert payload["target"] == target
    assert "flagSha256" not in payload
    with pytest.raises(ValueError, match="requires GET"):
        tool.prepare(request.model_copy(update={"method": "POST"}))
    with pytest.raises(ValueError, match="fixed to"):
        tool.prepare(
            request.model_copy(update={"target": "http://host.docker.internal:8780/admin"})
        )
    with pytest.raises(ValueError, match=r"host\.docker\.internal:8780"):
        tool.prepare(
            request.model_copy(update={"target": "http://example.com/backup/config.json.bak"})
        )


def test_trusted_worker_performs_one_fixed_ctf_web_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()
    captured: list[Any] = []
    body = json.dumps(
        {
            "challengeId": "web-backup-lab",
            "synthetic": True,
            "flag": FLAG,
        }
    ).encode()

    class Response:
        status = 200

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def read(self, limit: int) -> bytes:
            assert limit == worker.MAX_CTF_WEB_RESPONSE_BYTES + 1
            return body

    def urlopen(request: Any, timeout: int) -> Response:
        captured.append(request)
        assert timeout == 10
        return Response()

    monkeypatch.setattr(worker, "urlopen", urlopen)
    target = "http://host.docker.internal:8780/backup/config.json.bak"
    output = worker.ctf_web_backup_probe(
        {
            "target": target,
            "challengeId": "web-backup-lab",
            "scenarioId": "web.exposed-backup-config",
        }
    )

    assert len(captured) == 1
    assert captured[0].full_url == target
    assert captured[0].get_method() == "GET"
    assert output["candidateFlag"] == FLAG
    assert output["bodySha256"] == sha256(body).hexdigest()


@pytest.mark.parametrize(
    ("candidate", "expected_status"),
    [
        (FLAG, CTFSolveStatus.SOLVED),
        (None, CTFSolveStatus.UNSOLVED),
        ("PAJIN{wrong_flag}", CTFSolveStatus.INVALID_FLAG),
    ],
)
def test_ctf_multi_agent_run_classifies_flag_outcomes_and_seals_writeup(
    tmp_path: Path,
    candidate: str | None,
    expected_status: CTFSolveStatus,
) -> None:
    outcome, mode_pack = _run(tmp_path, candidate)

    artifacts = mode_pack.finalize(_challenge(), outcome)
    verification = verify_run_integrity(outcome.run_path)

    assert outcome.status is RunStatus.COMPLETED
    assert len(outcome.agents) == 5
    assert len(outcome.tool_results) == 1
    assert outcome.findings == []
    assert artifacts.result.status is expected_status
    assert artifacts.result_path.is_file()
    assert artifacts.writeup_path.is_file()
    assert verification.seal_count == 2
    writeup = artifacts.writeup_path.read_text(encoding="utf-8")
    assert "External scoreboard submission: `not performed`" in writeup
    if expected_status is CTFSolveStatus.SOLVED:
        assert FLAG in writeup


def test_ctf_web_run_cli_is_docker_only_and_never_submits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = ContractCTFWorker()
    requested_backends: list[str] = []

    def backend(name: str) -> ContractCTFWorker:
        requested_backends.append(name)
        return worker

    monkeypatch.setattr(cli, "_worker_backend", backend)
    result = CliRunner().invoke(
        cli.app,
        [
            "ctf-web-run",
            str(Path("examples/ctf-web-backup-lab.yaml").resolve()),
            "--output",
            str(tmp_path / "runs"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert requested_backends == ["docker"]
    assert f"Verified flag: {FLAG}" in result.output
    assert "No external scoreboard submission was performed." in result.output
