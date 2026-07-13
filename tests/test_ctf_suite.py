import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pajin.cli as cli
from pajin.domain.models import CampaignMode, ToolRiskTier
from pajin.domain.orchestration import AgentRole, RunStatus
from pajin.modes.ctf import (
    CTFChallengeManifest,
    CTFChallengeService,
    CTFFlagValidatorRuntime,
    CTFSolveStatus,
    CTFSuiteModePack,
    CTFTriagePlannerRuntime,
    load_ctf_challenge,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import ToolRegistry
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.workflow.multi_agent import MultiAgentCampaignRunner

WEB_FLAG = "PAJIN{fixed_web_backup_lab}"
CRYPTO_FLAG = "PAJIN{single_byte_xor_lab}"


def _challenges() -> list[CTFChallengeManifest]:
    return [
        load_ctf_challenge(Path("examples/ctf-web-backup-lab.yaml")),
        load_ctf_challenge(Path("examples/ctf-crypto-xor-lab.yaml")),
    ]


class ContractSuiteWorker:
    def __init__(
        self,
        *,
        web_candidate: str | None = WEB_FLAG,
        crypto_candidate: str | None = CRYPTO_FLAG,
    ) -> None:
        self.web_candidate = web_candidate
        self.crypto_candidate = crypto_candidate
        self.jobs: list[WorkerJob] = []

    async def run(self, job: WorkerJob) -> WorkerResult:
        self.jobs.append(job)
        payload = json.loads(job.stdin)
        now = datetime.now(UTC)
        if job.command == ["ctf-web-backup-probe"]:
            assert job.network is NetworkMode.EGRESS_PROXY
            assert job.egress_policy is not None
            candidate = self.web_candidate
            output = {
                "target": payload["target"],
                "challengeId": payload["challengeId"],
                "scenarioId": payload["scenarioId"],
                "status": 200 if candidate is not None else 404,
                "discovered": candidate is not None,
                "candidateFlag": candidate,
                "bodySha256": "0" * 64,
                "synthetic": True,
                "networkPerformed": True,
            }
        elif job.command == ["ctf-crypto-single-byte-xor"]:
            assert job.network is NetworkMode.NONE
            assert job.egress_policy is None
            candidate = self.crypto_candidate
            output = {
                "target": payload["target"],
                "challengeId": payload["challengeId"],
                "scenarioId": payload["scenarioId"],
                "artifactSha256": payload["artifactSha256"],
                "solved": candidate is not None,
                "candidateFlag": candidate,
                "key": 55 if candidate is not None else None,
                "attemptedKeys": 256,
                "synthetic": True,
                "networkPerformed": False,
            }
        else:
            raise AssertionError(f"unexpected Suite worker command: {job.command}")
        return WorkerResult(
            execution_id=job.execution_id,
            backend="ctf-suite-contract-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=now,
            finished_at=now,
        )


def _run(tmp_path: Path, worker: ContractSuiteWorker):
    registry = ToolRegistry()
    registry.register(CTFWebBackupProbeTool())
    registry.register(CTFCryptoXORTool())
    campaign = CTFChallengeService().compile_suite("web-crypto-suite", _challenges())
    runner = MultiAgentCampaignRunner(
        planner=CTFTriagePlannerRuntime(),
        validator=CTFFlagValidatorRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=worker,
        output_root=tmp_path,
    )
    return asyncio.run(runner.run(campaign))


def test_suite_compiler_intersects_approval_and_derives_combined_budget() -> None:
    web, crypto = _challenges()
    crypto_payload = crypto.model_dump(mode="json", by_alias=True)
    crypto_payload["spec"]["authorization"]["approvedAt"] = "2026-07-13T00:30:00Z"
    crypto_payload["spec"]["authorization"]["expiresAt"] = "2098-01-01T00:00:00Z"
    crypto = CTFChallengeManifest.model_validate(crypto_payload)

    campaign = CTFChallengeService().compile_suite(
        "web-crypto-suite",
        [crypto, web],
        evaluated_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
    )

    assert campaign.spec.mode is CampaignMode.CTF
    assert campaign.spec.access_profile == "mixed"
    assert [target.type for target in campaign.spec.targets] == ["ctf-web", "ctf-crypto"]
    assert campaign.spec.scope.allow == [target.endpoint for target in campaign.spec.targets]
    assert campaign.spec.authorization.approved_at == datetime(2026, 7, 13, 0, 30, tzinfo=UTC)
    assert campaign.spec.authorization.expires_at == datetime(2098, 1, 1, tzinfo=UTC)
    assert "members-sha256:" in campaign.spec.authorization.evidence
    rules = campaign.spec.rules_of_engagement
    assert rules.max_tool_risk_tier is ToolRiskTier.T1
    assert rules.allowed_methods == {"GET", "POST"}
    assert rules.allowed_tool_categories == {
        "crypto",
        "ctf",
        "discovery",
        "http",
        "offline-analysis",
        "web",
    }
    assert rules.allow_private_networks
    assert rules.max_requests_per_minute == 5
    assert campaign.spec.budgets.duration_seconds == 120
    assert campaign.spec.budgets.max_agents == 6
    assert campaign.spec.budgets.max_tool_calls == 2
    assert campaign.spec.budgets.max_model_calls == 0


def test_suite_compiler_rejects_ambiguous_members_and_authorization() -> None:
    web, crypto = _challenges()
    service = CTFChallengeService()

    with pytest.raises(ValueError, match="exactly two"):
        service.compile_suite("web-crypto-suite", [web])
    with pytest.raises(ValueError, match="challenge IDs must be unique"):
        service.compile_suite("web-crypto-suite", [web, web.model_copy(deep=True)])
    second_web_payload = web.model_dump(mode="json", by_alias=True)
    second_web_payload["metadata"]["name"] = "second-web-backup-lab"
    with pytest.raises(ValueError, match="one Web and one Crypto"):
        service.compile_suite(
            "web-crypto-suite",
            [web, CTFChallengeManifest.model_validate(second_web_payload)],
        )
    with pytest.raises(ValueError, match="DNS-style"):
        service.compile_suite("Bad Suite", [web, crypto])
    with pytest.raises(ValueError, match="intersection is not active"):
        service.compile_suite(
            "web-crypto-suite",
            [web, crypto],
            evaluated_at=datetime(2100, 1, 1, tzinfo=UTC),
        )

    other_approver = crypto.model_dump(mode="json", by_alias=True)
    other_approver["spec"]["authorization"]["approvedBy"] = "different-owner"
    with pytest.raises(ValueError, match="same approving authority"):
        service.compile_suite(
            "web-crypto-suite",
            [web, CTFChallengeManifest.model_validate(other_approver)],
        )

    web_window = web.model_dump(mode="json", by_alias=True)
    web_window["spec"]["authorization"]["expiresAt"] = "2026-07-14T00:00:00Z"
    crypto_window = crypto.model_dump(mode="json", by_alias=True)
    crypto_window["spec"]["authorization"]["approvedAt"] = "2026-07-15T00:00:00Z"
    crypto_window["spec"]["authorization"]["expiresAt"] = "2026-07-16T00:00:00Z"
    with pytest.raises(ValueError, match="do not overlap"):
        service.compile_suite(
            "web-crypto-suite",
            [
                CTFChallengeManifest.model_validate(web_window),
                CTFChallengeManifest.model_validate(crypto_window),
            ],
        )


def test_suite_run_spawns_category_specialists_and_seals_aggregate_result(
    tmp_path: Path,
) -> None:
    worker = ContractSuiteWorker()
    outcome = _run(tmp_path, worker)

    artifacts = CTFSuiteModePack().finalize(
        "web-crypto-suite",
        _challenges(),
        outcome,
    )
    verification = verify_run_integrity(outcome.run_path)

    assert outcome.status is RunStatus.COMPLETED
    assert len(outcome.agents) == 6
    assert sum(agent.role is AgentRole.SPECIALIST for agent in outcome.agents) == 2
    assert len(outcome.tool_results) == 2
    assert len(outcome.findings) == 2
    assert outcome.plan is not None
    assert {step.persona for step in outcome.plan.steps} == {
        "ctf-web-specialist",
        "ctf-crypto-specialist",
    }
    assert artifacts.result.summary.solved == 2
    assert {item.candidate_flag for item in artifacts.result.items} == {
        WEB_FLAG,
        CRYPTO_FLAG,
    }
    assert artifacts.result_path.name == "ctf-suite-result.json"
    assert artifacts.writeup_path.name == "ctf-suite-writeup.md"
    assert verification.seal_count == 2
    assert [job.command for job in worker.jobs] == [
        ["ctf-web-backup-probe"],
        ["ctf-crypto-single-byte-xor"],
    ]
    writeup = artifacts.writeup_path.read_text(encoding="utf-8")
    assert WEB_FLAG in writeup
    assert CRYPTO_FLAG in writeup
    assert "External scoreboard submission: `not performed`" in writeup


def test_suite_finalization_rejects_manifest_drift_after_run(tmp_path: Path) -> None:
    challenges = _challenges()
    outcome = _run(tmp_path, ContractSuiteWorker())
    crypto_payload = challenges[1].model_dump(mode="json", by_alias=True)
    crypto_payload["spec"]["flag"]["sha256"] = "0" * 64
    tampered_challenges = [
        challenges[0],
        CTFChallengeManifest.model_validate(crypto_payload),
    ]

    with pytest.raises(ValueError, match="does not match the CTF Suite"):
        CTFSuiteModePack().finalize(
            "web-crypto-suite",
            tampered_challenges,
            outcome,
        )


@pytest.mark.parametrize(
    ("web_candidate", "crypto_candidate", "unsolved", "invalid"),
    [
        (None, CRYPTO_FLAG, 1, 0),
        ("PAJIN{wrong_web_flag}", CRYPTO_FLAG, 0, 1),
    ],
)
def test_suite_result_preserves_independent_failure_statuses(
    tmp_path: Path,
    web_candidate: str | None,
    crypto_candidate: str,
    unsolved: int,
    invalid: int,
) -> None:
    outcome = _run(
        tmp_path,
        ContractSuiteWorker(
            web_candidate=web_candidate,
            crypto_candidate=crypto_candidate,
        ),
    )

    result = CTFSuiteModePack().finalize("web-crypto-suite", _challenges(), outcome).result

    assert result.summary.solved == 1
    assert result.summary.unsolved == unsolved
    assert result.summary.invalid_flag == invalid
    assert result.items[0].status in {
        CTFSolveStatus.UNSOLVED,
        CTFSolveStatus.INVALID_FLAG,
    }
    assert result.items[1].status is CTFSolveStatus.SOLVED


def test_ctf_suite_cli_is_docker_only_and_never_submits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = ContractSuiteWorker()
    requested_backends: list[str] = []

    def backend(name: str) -> ContractSuiteWorker:
        requested_backends.append(name)
        return worker

    monkeypatch.setattr(cli, "_worker_backend", backend)
    result = CliRunner().invoke(
        cli.app,
        [
            "ctf-suite-run",
            "web-crypto-suite",
            str(Path("examples/ctf-web-backup-lab.yaml").resolve()),
            str(Path("examples/ctf-crypto-xor-lab.yaml").resolve()),
            "--output",
            str(tmp_path / "runs"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert requested_backends == ["docker"]
    assert "Challenges" in result.output
    assert f"Verified flag (web-backup-lab): {WEB_FLAG}" in result.output
    assert f"Verified flag (crypto-xor-lab): {CRYPTO_FLAG}" in result.output
    assert "No external scoreboard submission was performed." in result.output
