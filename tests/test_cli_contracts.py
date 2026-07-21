from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import pajin.cli as cli
from pajin.domain.orchestration import RunStatus
from pajin.modes.ai_redteam.models import MetricStatus
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus

KISA_MANIFEST = Path("examples/kisa-ai-chat-lab.yaml")


def _worker_result(
    stdout: str,
    *,
    status: WorkerStatus = WorkerStatus.SUCCEEDED,
    exit_code: int | None = 0,
    stderr: str = "",
) -> WorkerResult:
    now = datetime.now(UTC)
    return WorkerResult(
        execution_id="exec_cli_contract",
        backend="cli-contract",
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=now,
        finished_at=now,
    )


def test_local_run_does_not_announce_completion_when_a_tool_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "failed-run" / "report.md"

    class FailedLocalRunner:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def run(self, _campaign: object) -> SimpleNamespace:
            return SimpleNamespace(
                run_id="failed-run",
                tool_results=[SimpleNamespace(success=False)],
                findings=[],
                validation=SimpleNamespace(decisions=[]),
                report_path=report_path,
            )

    monkeypatch.setattr(cli, "_worker_backend", lambda _worker: object())
    monkeypatch.setattr(cli, "LocalCampaignRunner", FailedLocalRunner)

    result = CliRunner().invoke(cli.app, ["run", str(KISA_MANIFEST)])

    assert result.exit_code == 1, result.output
    assert "Local campaign failed" in result.output
    assert "1 tool call(s) failed" in result.output
    assert "Campaign completed" not in result.output


def test_local_run_normalizes_runtime_errors_without_traceback_or_forged_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenLocalRunner:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def run(self, _campaign: object) -> None:
            raise RuntimeError(
                "backend exploded\n[bold green]Campaign completed[/bold green]\ud800"
            )

    monkeypatch.setattr(cli, "_worker_backend", lambda _worker: object())
    monkeypatch.setattr(cli, "LocalCampaignRunner", BrokenLocalRunner)

    result = CliRunner().invoke(cli.app, ["run", str(KISA_MANIFEST)])

    assert result.exit_code == 1, result.output
    normalized_output = " ".join(result.output.split())
    assert (
        "Local campaign execution failed: "
        "exception_type=RuntimeError; stage=cli-command; detail=omitted"
    ) in normalized_output
    assert "backend exploded" not in result.output
    assert "Traceback" not in result.output
    assert "\nCampaign completed" not in result.output


@pytest.mark.parametrize(
    ("arguments", "expected_worker"),
    [
        (["run", str(KISA_MANIFEST)], "docker"),
        (["multi-run", str(KISA_MANIFEST)], "docker"),
        (
            ["provider-check", "examples/provider-openai-compatible-lab.yaml"],
            "docker",
        ),
        (["provider-agent-run", str(KISA_MANIFEST)], "docker"),
        (["tool-loop-run", "examples/tool-loop-lab.yaml"], "docker"),
        (
            ["tool-loop-approval-check", "examples/tool-loop-approval-lab.yaml"],
            "docker",
        ),
        (["multi-cancel-check", "examples/multi-agent-cancel.yaml"], "docker"),
        (["kisa-run", str(KISA_MANIFEST)], "docker"),
    ],
)
def test_commands_route_their_documented_default_worker(
    arguments: list[str],
    expected_worker: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected: list[str] = []

    def capture(worker: str) -> object:
        selected.append(worker)
        raise ValueError("stop after backend selection")

    monkeypatch.setattr(cli, "_worker_backend", capture)

    result = CliRunner().invoke(cli.app, arguments)

    assert result.exit_code == 2, result.output
    assert selected == [expected_worker]
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    ("command", "manifest"),
    [
        ("run", Path("examples/ai-redteam.yaml")),
        ("multi-run", Path("examples/multi-agent.yaml")),
    ],
)
def test_explicit_simulated_run_is_labeled_in_cli_and_sealed_artifacts(
    command: str,
    manifest: Path,
    tmp_path: Path,
) -> None:
    output = tmp_path / command

    result = CliRunner().invoke(
        cli.app,
        [
            command,
            str(manifest),
            "--worker",
            "simulated",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert result.output.count("SIMULATED / NOT REAL TARGET EVIDENCE") == 1
    contexts = list(output.rglob("execution-context.json"))
    assert len(contexts) == 1
    run_path = contexts[0].parent
    context = json.loads(contexts[0].read_text(encoding="utf-8"))
    summary = json.loads((run_path / "run.json").read_text(encoding="utf-8"))
    report = (run_path / "report.md").read_text(encoding="utf-8")
    events = [
        json.loads(line)
        for line in (run_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    started = next(event for event in events if event["event_type"] == "campaign.started")

    assert context["backend"] == "simulated"
    assert context["simulated"] is True
    assert context["evidenceScope"] == "simulated-development-only"
    assert summary["executionContext"] == "execution-context.json"
    assert summary["workerBackend"] == "simulated"
    assert summary["simulated"] is True
    assert started["payload"]["workerBackend"] == "simulated"
    assert started["payload"]["simulated"] is True
    assert "SIMULATED / NOT REAL TARGET EVIDENCE" in report
    assert "- Worker backend: `simulated`" in report
    assert verify_run_integrity(run_path).valid
    if command == "multi-run":
        assert result.output.count("Needs review:") == 1


def test_kisa_retest_routes_its_documented_default_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    selected: list[str] = []

    def capture(worker: str) -> object:
        selected.append(worker)
        raise ValueError("stop after backend selection")

    monkeypatch.setattr(cli, "_worker_backend", capture)

    result = CliRunner().invoke(
        cli.app,
        ["kisa-retest", str(baseline), str(KISA_MANIFEST)],
    )

    assert result.exit_code == 2, result.output
    assert selected == ["docker"]
    assert "Traceback" not in result.output


def test_kisa_run_returns_failure_when_an_evaluation_threshold_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_path = tmp_path / "run"

    class FakeRunner:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def run(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(
                status=RunStatus.COMPLETED,
                run_id="kisa-threshold-failure",
                run_path=run_path,
                findings=[],
                validation=SimpleNamespace(decisions=[]),
            )

    class FakeCoordinator:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def reproduce(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(verified_results={}, records=[])

    class FakeModePack:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def evaluate(self, *_args: object) -> SimpleNamespace:
            return SimpleNamespace(
                assessment=SimpleNamespace(
                    coverage=SimpleNamespace(coverage_rate=1.0),
                    metrics=[SimpleNamespace(status=MetricStatus.FAIL)],
                    checklist_summary=SimpleNamespace(yes=1, no=0, needs_review=0),
                ),
                report_path=run_path / "kisa-report.md",
                checklist_path=run_path / "kisa-checklist.json",
            )

    monkeypatch.setattr(cli, "_worker_backend", lambda _worker: object())
    monkeypatch.setattr(cli, "MultiAgentCampaignRunner", FakeRunner)
    monkeypatch.setattr(cli, "KISAReplayCoordinator", FakeCoordinator)
    monkeypatch.setattr(cli, "KISAModePack", FakeModePack)

    result = CliRunner().invoke(
        cli.app,
        ["kisa-run", str(KISA_MANIFEST), "--output", str(tmp_path)],
    )

    assert result.exit_code == 1, result.output
    assert "Failed metric thresholds" in result.output
    assert "1" in result.output


def test_kisa_run_labels_simulated_evidence_even_when_execution_fails(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli.app,
        [
            "kisa-run",
            str(KISA_MANIFEST),
            "--worker",
            "simulated",
            "--output",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 1, result.output
    assert result.output.count("SIMULATED / NOT REAL TARGET EVIDENCE") == 1
    assert "Worker backend: simulated" in result.output
    assert "Run status" in result.output
    assert "failed" in result.output


@pytest.mark.parametrize(
    "isolation_stdout",
    [
        (
            '{"nonRoot":false,"nonRoot":true,"networkBlocked":true,'
            '"rootReadOnly":true,"workspaceWritable":true,'
            '"capabilitiesDropped":true,"noNewPrivileges":true}'
        ),
        (
            '{"nonRoot":true,"networkBlocked":true,"rootReadOnly":true,'
            '"workspaceWritable":true,"capabilitiesDropped":true,'
            '"noNewPrivileges":true,"memoryMax":NaN}'
        ),
    ],
    ids=["duplicate-key", "non-finite-number"],
)
def test_worker_check_rejects_ambiguous_worker_json(
    isolation_stdout: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeDockerWorker:
        async def run(self, job: WorkerJob) -> WorkerResult:
            command = job.command
            if command == ["isolation-check"]:
                return _worker_result(isolation_stdout)
            assert command == ["sleep-check"]
            return _worker_result(
                "",
                status=WorkerStatus.TIMED_OUT,
                exit_code=-9,
            )

    monkeypatch.setattr(
        cli,
        "DockerWorkerBackend",
        lambda **_kwargs: FakeDockerWorker(),
    )

    result = CliRunner().invoke(cli.app, ["worker-check"])

    assert result.exit_code == 1, result.output
    assert "Invalid worker-check output" in result.output


@pytest.mark.parametrize(("typed_rejections", "expected_exit"), [(True, 0), (False, 1)])
def test_mcp_check_requires_exact_typed_catalog_rejections(
    monkeypatch: pytest.MonkeyPatch,
    typed_rejections: bool,
    expected_exit: int,
) -> None:
    expected = {
        "vulnerable": True,
        "observation": "untrusted text contains an instruction-hijacking pattern",
    }

    class FakeDockerWorker:
        async def run(self, job: WorkerJob) -> WorkerResult:
            payload = json.loads(job.stdin)
            if payload["serverId"] == "demo-security" and payload["toolName"] == "inspect_text":
                return _worker_result(
                    json.dumps(
                        {
                            "isError": False,
                            "structuredContent": expected,
                            "content": [{"type": "text", "text": json.dumps(expected)}],
                        }
                    )
                )
            code = (
                "server-not-registered"
                if payload["serverId"] == "unregistered-server"
                else "tool-not-registered"
            )
            if typed_rejections:
                return _worker_result(
                    json.dumps(
                        {
                            "isError": True,
                            "structuredContent": {"rejectionCode": code},
                            "content": [],
                        }
                    )
                )
            return _worker_result(
                "",
                status=WorkerStatus.FAILED,
                exit_code=70,
                stderr=(
                    "MCP server ID is not registered"
                    if code == "server-not-registered"
                    else "MCP tool is not registered for this server"
                ),
            )

    monkeypatch.setattr(
        cli,
        "DockerWorkerBackend",
        lambda **_kwargs: FakeDockerWorker(),
    )

    result = CliRunner().invoke(cli.app, ["mcp-check"])

    assert result.exit_code == expected_exit, result.output
    assert "registered MCP call" in result.output
    assert "unknown server rejected with typed code" in result.output
    assert "unknown tool rejected with typed code" in result.output


def _sealed_cli_check_run(tmp_path: Path) -> RunStore:
    store = RunStore.create(tmp_path, "cli-check")
    store.append_event("campaign.started", {})
    store.write_json("secrets.json", [])
    store.seal()
    return store


def test_provider_checks_do_not_use_unbounded_path_convenience_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _sealed_cli_check_run(tmp_path)
    outcome = SimpleNamespace(
        run_id=store.run_id,
        run_path=store.path,
        status=RunStatus.COMPLETED,
        tool_results=[],
    )

    def fail_unbounded_read(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("CLI checks must use bounded verified Run reads")

    monkeypatch.setattr(Path, "read_text", fail_unbounded_read)
    monkeypatch.setattr(Path, "read_bytes", fail_unbounded_read)

    checks = cli._provider_checks(outcome, credential="absent-secret")

    assert checks["credential absent from run artifacts"]


def test_provider_checks_fail_closed_on_unsealed_symlink_artifact(tmp_path: Path) -> None:
    store = _sealed_cli_check_run(tmp_path)
    victim = tmp_path / "operator-secret.txt"
    victim.write_text("provider-secret", encoding="utf-8")
    (store.path / "unsealed-link.txt").symlink_to(victim)
    outcome = SimpleNamespace(
        run_id=store.run_id,
        run_path=store.path,
        status=RunStatus.COMPLETED,
        tool_results=[],
    )

    with pytest.raises(ValueError, match="Run artifacts cannot contain symbolic links"):
        cli._provider_checks(outcome, credential="provider-secret")
