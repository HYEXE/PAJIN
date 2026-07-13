import asyncio
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import pajin.cli as cli
from pajin.domain.models import CampaignMode, ToolRequest, ToolRiskTier
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
from pajin.tools.ctf import (
    CTF_CRYPTO_XOR_TOOL_ID,
    CTFCryptoXORTool,
    crypto_artifact_target,
)
from pajin.workflow.multi_agent import MultiAgentCampaignRunner

CRYPTO_FLAG = "PAJIN{single_byte_xor_lab}"
ARTIFACT_SHA256 = "cd63642e4c282f36a73bf4834fbb9587e9b46053823a0b0728e4ccf5904a7880"
CIPHERTEXT_HEX = "67767d7e794c445e59505b5268554e4352684f5845685b56554a"


def _challenge() -> CTFChallengeManifest:
    return load_ctf_challenge(Path("examples/ctf-crypto-xor-lab.yaml"))


def _worker_entry() -> ModuleType:
    path = Path("containers/worker/worker_entry.py")
    spec = importlib.util.spec_from_file_location("pajin_ctf_crypto_worker_entry", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ContractCryptoWorker:
    def __init__(self, candidate: str | None = CRYPTO_FLAG) -> None:
        self.candidate = candidate
        self.jobs: list[WorkerJob] = []

    async def run(self, job: WorkerJob) -> WorkerResult:
        self.jobs.append(job)
        assert job.command == ["ctf-crypto-single-byte-xor"]
        assert job.network is NetworkMode.NONE
        assert job.egress_policy is None
        payload = json.loads(job.stdin)
        now = datetime.now(UTC)
        output = {
            "target": payload["target"],
            "challengeId": payload["challengeId"],
            "scenarioId": payload["scenarioId"],
            "artifactSha256": payload["artifactSha256"],
            "solved": self.candidate is not None,
            "candidateFlag": self.candidate,
            "key": 55 if self.candidate is not None else None,
            "attemptedKeys": 256,
            "synthetic": True,
            "networkPerformed": False,
        }
        return WorkerResult(
            execution_id=job.execution_id,
            backend="ctf-crypto-contract-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=now,
            finished_at=now,
        )


def test_crypto_challenge_compiles_to_offline_content_addressed_policy() -> None:
    challenge = _challenge()
    campaign = CTFChallengeService().compile_campaign(
        challenge,
        evaluated_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
    )

    assert campaign.spec.mode is CampaignMode.CTF
    assert campaign.spec.access_profile == "inline-artifact"
    target = campaign.spec.targets[0]
    assert target.type == "ctf-crypto"
    assert target.endpoint == crypto_artifact_target("crypto-xor-lab", ARTIFACT_SHA256)
    assert target.simulation["artifactSha256"] == ARTIFACT_SHA256
    assert target.simulation["ciphertextHex"] == CIPHERTEXT_HEX
    assert "candidateFlag" not in target.simulation
    rules = campaign.spec.rules_of_engagement
    assert rules.max_tool_risk_tier is ToolRiskTier.T0
    assert rules.allowed_methods == {"POST"}
    assert rules.allowed_tool_categories == {"crypto", "ctf", "offline-analysis"}
    assert not rules.allow_private_networks
    assert "network-access" in rules.prohibit


def test_crypto_manifest_rejects_artifact_tampering_and_category_mixing() -> None:
    payload = _challenge().model_dump(mode="json", by_alias=True)
    payload["spec"]["artifact"]["sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="does not match"):
        CTFChallengeManifest.model_validate(payload)

    payload = _challenge().model_dump(mode="json", by_alias=True)
    payload["spec"]["artifact"]["data"] = CIPHERTEXT_HEX.upper()
    with pytest.raises(ValidationError, match="lowercase hexadecimal"):
        CTFChallengeManifest.model_validate(payload)

    payload = _challenge().model_dump(mode="json", by_alias=True)
    payload["spec"]["scope"] = {
        "entryPoint": "http://host.docker.internal:8780/backup/config.json.bak"
    }
    with pytest.raises(ValidationError, match="forbids scope"):
        CTFChallengeManifest.model_validate(payload)


def test_crypto_tool_accepts_only_content_addressed_bounded_analysis() -> None:
    target = crypto_artifact_target("crypto-xor-lab", ARTIFACT_SHA256)
    request = ToolRequest(
        agent_id="agent:ctf-crypto-specialist",
        tool_id=CTF_CRYPTO_XOR_TOOL_ID,
        target=target,
        method="POST",
        arguments={
            "challengeId": "crypto-xor-lab",
            "scenarioId": "crypto.single-byte-xor",
            "artifactSha256": ARTIFACT_SHA256,
            "ciphertextHex": CIPHERTEXT_HEX,
        },
    )
    tool = CTFCryptoXORTool()

    job = tool.prepare(request)

    assert job.network is NetworkMode.NONE
    assert job.egress_policy is None
    assert job.command == ["ctf-crypto-single-byte-xor"]
    payload = json.loads(job.stdin)
    assert payload["artifactSha256"] == ARTIFACT_SHA256
    assert "flagSha256" not in payload
    with pytest.raises(ValueError, match="requires POST"):
        tool.prepare(request.model_copy(update={"method": "GET"}))
    with pytest.raises(ValueError, match="content address"):
        tool.prepare(request.model_copy(update={"target": "http://artifact.invalid/wrong"}))
    tampered = dict(request.arguments)
    tampered["ciphertextHex"] = "00"
    with pytest.raises(ValidationError, match="does not match"):
        tool.prepare(request.model_copy(update={"arguments": tampered}))


def test_trusted_worker_solves_exactly_the_bounded_xor_keyspace() -> None:
    worker = _worker_entry()
    target = crypto_artifact_target("crypto-xor-lab", ARTIFACT_SHA256)

    output = worker.ctf_crypto_single_byte_xor(
        {
            "target": target,
            "challengeId": "crypto-xor-lab",
            "scenarioId": "crypto.single-byte-xor",
            "artifactSha256": ARTIFACT_SHA256,
            "ciphertextHex": CIPHERTEXT_HEX,
        }
    )

    assert output["candidateFlag"] == CRYPTO_FLAG
    assert output["key"] == 55
    assert output["attemptedKeys"] == 256
    assert output["networkPerformed"] is False
    with pytest.raises(ValueError, match="SHA-256 does not match"):
        worker.ctf_crypto_single_byte_xor(
            {
                "target": crypto_artifact_target("crypto-xor-lab", "0" * 64),
                "challengeId": "crypto-xor-lab",
                "scenarioId": "crypto.single-byte-xor",
                "artifactSha256": "0" * 64,
                "ciphertextHex": CIPHERTEXT_HEX,
            }
        )


def test_crypto_multi_agent_run_routes_specialist_and_seals_result(tmp_path: Path) -> None:
    challenge = _challenge()
    campaign = CTFChallengeService().compile_campaign(challenge)
    registry = ToolRegistry()
    registry.register(CTFCryptoXORTool())
    worker = ContractCryptoWorker()
    runner = MultiAgentCampaignRunner(
        planner=CTFTriagePlannerRuntime(),
        validator=CTFFlagValidatorRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )

    outcome = asyncio.run(runner.run(campaign))
    artifacts = CTFModePack().finalize(challenge, outcome)
    verification = verify_run_integrity(outcome.run_path)

    assert outcome.status is RunStatus.COMPLETED
    assert len(outcome.agents) == 5
    assert len(outcome.tool_results) == 1
    assert len(outcome.findings) == 1
    assert outcome.findings[0].threat_class == "CTF-CRYPTO"
    assert outcome.plan is not None
    assert outcome.plan.steps[0].persona == "ctf-crypto-specialist"
    assert artifacts.result.status is CTFSolveStatus.SOLVED
    assert artifacts.result.candidate_flag == CRYPTO_FLAG
    assert verification.seal_count == 2
    assert worker.jobs[0].network is NetworkMode.NONE
    assert "classified the typed challenge as crypto" in artifacts.writeup_path.read_text(
        encoding="utf-8"
    )


def test_generic_ctf_cli_routes_crypto_and_web_alias_rejects_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = ContractCryptoWorker()
    requested_backends: list[str] = []

    def backend(name: str) -> ContractCryptoWorker:
        requested_backends.append(name)
        return worker

    monkeypatch.setattr(cli, "_worker_backend", backend)
    challenge_path = str(Path("examples/ctf-crypto-xor-lab.yaml").resolve())
    result = CliRunner().invoke(
        cli.app,
        ["ctf-run", challenge_path, "--output", str(tmp_path / "runs")],
    )

    assert result.exit_code == 0, result.output
    assert requested_backends == ["docker"]
    assert f"Verified flag: {CRYPTO_FLAG}" in result.output
    assert "No external scoreboard submission was performed." in result.output

    rejected = CliRunner().invoke(
        cli.app,
        ["ctf-web-run", challenge_path, "--output", str(tmp_path / "rejected")],
    )
    assert rejected.exit_code == 2
    assert "accepts only the web CTF category" in rejected.output
    assert requested_backends == ["docker"]
