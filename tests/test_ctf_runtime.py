import asyncio
import importlib.util
import json
from base64 import b64decode, b64encode
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from typer.testing import CliRunner

import pajin.cli as cli
import pajin.modes.ctf.evidence as ctf_evidence
import pajin.modes.ctf.service as ctf_service
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
from pajin.runtime.store import RunIntegrityError, verify_run_integrity
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
        response = {
            "challengeId": payload["challengeId"],
            "synthetic": True,
            "flag": self.candidate,
        }
        body = json.dumps(response, separators=(",", ":")).encode()
        output = {
            "target": payload["target"],
            "challengeId": payload["challengeId"],
            "scenarioId": payload["scenarioId"],
            "status": 200 if self.candidate is not None else 404,
            "discovered": self.candidate is not None,
            "candidateFlag": self.candidate,
            "bodySha256": sha256(body).hexdigest(),
            "responseBodyBase64": b64encode(body).decode("ascii"),
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


def _trusted_docker_backend(
    worker: ContractCTFWorker,
    *,
    forge_body_digest: bool = False,
    forge_candidate_flag: bool = False,
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
        output = json.loads(result.stdout)
        response_body = b64decode(output["responseBodyBase64"], validate=True)
        response = json.loads(response_body)
        receipt = {
            "event": "allow",
            "receiptVersion": EGRESS_HTTP_RECEIPT_VERSION,
            "sequence": 1,
            "method": "GET",
            "target": audit_http_target(output["target"]),
            "targetSha256": http_target_sha256(output["target"]),
            "address": "172.17.0.1",
            "status": output["status"],
            "responseBodySha256": sha256(response_body).hexdigest(),
            "responseJsonSha256": _canonical_digest(response),
        }
        if forge_target_digest:
            receipt["targetSha256"] = "0" * 64
        network_log = "\n".join(
            [
                json.dumps({"event": "ready", "port": 8080}, separators=(",", ":")),
                json.dumps(receipt, separators=(",", ":")),
            ]
        )
        if forge_body_digest:
            output["bodySha256"] = "f" * 64
            result = result.model_copy(update={"stdout": json.dumps(output)})
        if forge_candidate_flag:
            output["candidateFlag"] = "PAJIN{forged_worker_claim}"
            result = result.model_copy(update={"stdout": json.dumps(output)})
        return result.model_copy(update={"backend": "docker", "network_log": network_log})

    backend.run = run  # type: ignore[method-assign]
    return backend


def _run(tmp_path: Path, candidate: str | None = FLAG) -> tuple[MultiAgentRunOutcome, CTFModePack]:
    registry = ToolRegistry()
    registry.register(CTFWebBackupProbeTool())
    worker = ContractCTFWorker(candidate)
    runner = MultiAgentCampaignRunner(
        planner=CTFTriagePlannerRuntime(),
        validator=CTFFlagValidatorRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=_trusted_docker_backend(worker),
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

    class Opener:
        def open(self, request: Any, timeout: int) -> Response:
            captured.append(request)
            assert timeout == 10
            return Response()

    monkeypatch.setattr(worker, "_HTTP_OPENER", Opener())
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
    assert b64decode(output["responseBodyBase64"], validate=True) == body


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


def test_ctf_finalization_uses_campaign_from_authoritative_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, mode_pack = _run(tmp_path)
    execution = ctf_evidence.load_authoritative_ctf_execution(outcome)
    drifted_campaign = execution.campaign.model_copy(
        update={
            "metadata": execution.campaign.metadata.model_copy(
                update={"description": "campaign from a substituted snapshot"}
            )
        }
    )

    def substituted_execution(
        observed_outcome: MultiAgentRunOutcome,
    ) -> ctf_evidence.SealedCTFExecution:
        assert observed_outcome is outcome
        return replace(execution, campaign=drifted_campaign)

    monkeypatch.setattr(
        ctf_service,
        "load_authoritative_ctf_execution",
        substituted_execution,
    )

    with pytest.raises(ValueError, match="does not match the CTF challenge"):
        mode_pack.finalize(_challenge(), outcome)


def test_ctf_authoritative_campaign_rejects_duplicate_json_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, _ = _run(tmp_path)
    original_load = ctf_evidence.load_verified_run_artifacts
    duplicate_campaign = b'{"apiVersion":"pajin.dev/v1alpha1","apiVersion":"pajin.dev/v1alpha1"}'

    class CampaignOverrideSnapshot:
        def __init__(self, snapshot: Any) -> None:
            self.verification = snapshot.verification
            self._snapshot = snapshot

        def artifact_bytes(self, relative_path: str) -> bytes:
            if relative_path == "campaign.json":
                return duplicate_campaign
            return self._snapshot.artifact_bytes(relative_path)

    def load_with_duplicate_campaign(*args: Any, **kwargs: Any) -> Any:
        return CampaignOverrideSnapshot(original_load(*args, **kwargs))

    monkeypatch.setattr(
        ctf_evidence,
        "load_verified_run_artifacts",
        load_with_duplicate_campaign,
    )

    with pytest.raises(ValueError, match="execution metadata is invalid"):
        ctf_evidence.load_authoritative_ctf_execution(outcome)


def test_ctf_authoritative_execution_rejects_snapshot_phase_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, _ = _run(tmp_path)
    original_load = ctf_evidence.load_verified_run_artifacts
    load_count = 0

    def load_with_substituted_second_phase(*args: Any, **kwargs: Any) -> Any:
        nonlocal load_count
        snapshot = original_load(*args, **kwargs)
        load_count += 1
        if load_count != 2:
            return snapshot
        substituted_verification = snapshot.verification.model_copy(
            update={"root_digest": "0" * 64}
        )
        return replace(snapshot, verification=substituted_verification)

    monkeypatch.setattr(
        ctf_evidence,
        "load_verified_run_artifacts",
        load_with_substituted_second_phase,
    )

    with pytest.raises(ValueError, match="changed while its evidence paths were derived"):
        ctf_evidence.load_authoritative_ctf_execution(outcome)
    assert load_count == 2


def test_ctf_authoritative_campaign_enforces_snapshot_size_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, _ = _run(tmp_path)
    monkeypatch.setattr(ctf_evidence, "_MAX_CAMPAIGN_JSON_BYTES", 1)

    with pytest.raises(RunIntegrityError, match=r"campaign\.json"):
        ctf_evidence.load_authoritative_ctf_execution(outcome)


@pytest.mark.parametrize(
    "forgery",
    ["untrusted", "body-digest", "candidate-flag", "target-digest"],
)
def test_ctf_web_worker_claim_cannot_solve_without_matching_host_receipt(
    tmp_path: Path,
    forgery: str,
) -> None:
    challenge = _challenge()
    campaign = CTFChallengeService().compile_campaign(challenge)
    registry = ToolRegistry()
    registry.register(CTFWebBackupProbeTool())
    worker = ContractCTFWorker()
    if forgery == "body-digest":
        backend = _trusted_docker_backend(worker, forge_body_digest=True)
    elif forgery == "candidate-flag":
        backend = _trusted_docker_backend(worker, forge_candidate_flag=True)
    elif forgery == "target-digest":
        backend = _trusted_docker_backend(worker, forge_target_digest=True)
    else:
        backend = worker
    runner = MultiAgentCampaignRunner(
        planner=CTFTriagePlannerRuntime(),
        validator=CTFFlagValidatorRuntime(),
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


def test_ctf_web_run_cli_is_docker_only_and_never_submits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = ContractCTFWorker()
    requested_backends: list[str] = []

    trusted_worker = _trusted_docker_backend(worker)

    def backend(name: str) -> DockerWorkerBackend:
        requested_backends.append(name)
        return trusted_worker

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
