from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import pajin.cli as cli
from pajin.domain.models import CampaignMode
from pajin.domain.orchestration import RunStatus
from pajin.modes.ai_redteam.retest import RegressionStatus


@pytest.mark.parametrize(
    ("regression", "expected_exit_code"),
    [
        (RegressionStatus.PASS, 0),
        (RegressionStatus.FAIL, 1),
    ],
)
def test_kisa_retest_cli_requires_fixed_findings_and_regression_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    regression: RegressionStatus,
    expected_exit_code: int,
) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    retest_run = tmp_path / "runs" / "retest-run"
    retest_run.mkdir(parents=True)
    shared_state: dict[str, object] = {}

    class FakeRetestService:
        def create_remediation_plan(self, baseline_run: Path) -> SimpleNamespace:
            assert baseline_run == baseline
            return SimpleNamespace(actions=[object()], path=baseline / "remediation-plan.json")

        def build_retest_contexts(
            self,
            baseline_run: Path,
            retest_run_path: Path,
        ) -> dict[str, object]:
            assert baseline_run == baseline
            assert retest_run_path == retest_run
            return {"candidate:1": object()}

        def compare(
            self,
            baseline_run: Path,
            retest_run_path: Path,
            *,
            replay_batch: object,
        ) -> SimpleNamespace:
            assert baseline_run == baseline
            assert retest_run_path == retest_run
            assert replay_batch is shared_state["batch"]
            summary = SimpleNamespace(
                fixed=1,
                still_vulnerable=0,
                inconclusive=0,
                new_findings=0,
                regression=regression,
            )
            return SimpleNamespace(
                assessment=SimpleNamespace(summary=summary),
                report_path=retest_run / "kisa-retest-report.md",
                remediation_plan_path=retest_run / "remediation-plan.json",
                checklist_overlay_path=retest_run / "kisa-checklist-overlay.json",
            )

    class FakePlanner:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def plan(self, _campaign: object) -> SimpleNamespace:
            return SimpleNamespace(steps=[object(), object()])

    class FakeRunner:
        def __init__(self, **kwargs: object) -> None:
            shared_state["runner_tools"] = kwargs["tools"]
            shared_state["runner_policy"] = kwargs["policy"]

        async def run(self, _campaign: object, **kwargs: object) -> SimpleNamespace:
            shared_state["budget"] = kwargs["budget"]
            shared_state["rate_limits"] = kwargs["rate_limits"]
            return SimpleNamespace(
                status=RunStatus.COMPLETED,
                run_id="retest-run",
                run_path=retest_run,
                report_path=retest_run / "report.md",
            )

    class FakeModePack:
        def __init__(self, **_kwargs: object) -> None:
            raise AssertionError("normal-only retest Runs must not be evaluated as attack Runs")

    class FakeCoordinator:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs["tools"] is shared_state["runner_tools"]
            assert kwargs["policy"] is shared_state["runner_policy"]

        async def reproduce(self, *_args: object, **kwargs: object) -> SimpleNamespace:
            assert kwargs["budget"] is shared_state["budget"]
            assert kwargs["rate_limits"] is shared_state["rate_limits"]
            assert set(kwargs["contexts"]) == {"candidate:1"}
            batch = SimpleNamespace(verified_results={"candidate:1": object()})
            shared_state["batch"] = batch
            return batch

    monkeypatch.setattr(cli, "_worker_backend", lambda _worker: object())
    monkeypatch.setattr(cli, "KISARetestService", FakeRetestService)
    monkeypatch.setattr(cli, "KISARetestPlannerRuntime", FakePlanner)
    monkeypatch.setattr(cli, "MultiAgentCampaignRunner", FakeRunner)
    monkeypatch.setattr(cli, "KISAModePack", FakeModePack)
    monkeypatch.setattr(cli, "KISARetestReplayCoordinator", FakeCoordinator)

    result = CliRunner().invoke(
        cli.app,
        [
            "kisa-retest",
            str(baseline),
            "examples/kisa-ai-chat-lab.yaml",
            "--output",
            str(tmp_path / "runs"),
        ],
    )

    assert result.exit_code == expected_exit_code, result.output
    assert "Fixed" in result.output
    assert "Verified negative replay receipts" in result.output
    assert "New threat discovery" in result.output
    assert "Not assessed" in result.output
    assert "Scope note:" in result.output
    assert "pajin kisa-run" in result.output
    assert "Worker backend: custom" in result.output


def test_kisa_retest_cli_reserves_normal_probe_retry_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()

    class FakeRetestService:
        def create_remediation_plan(self, _baseline_run: Path) -> SimpleNamespace:
            return SimpleNamespace(actions=[object()], path=baseline / "remediation-plan.json")

    class FakePlanner:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def plan(self, _campaign: object) -> SimpleNamespace:
            return SimpleNamespace(steps=[object(), object()])

    campaign = SimpleNamespace(
        spec=SimpleNamespace(
            mode=CampaignMode.AI_REDTEAM,
            budgets=SimpleNamespace(max_tool_calls=6),
        )
    )
    monkeypatch.setattr(cli, "load_manifest", lambda _manifest: campaign)
    monkeypatch.setattr(cli, "_worker_backend", lambda _worker: object())
    monkeypatch.setattr(cli, "KISARetestService", FakeRetestService)
    monkeypatch.setattr(cli, "KISARetestPlannerRuntime", FakePlanner)

    result = CliRunner().invoke(
        cli.app,
        [
            "kisa-retest",
            str(baseline),
            "examples/kisa-ai-chat-lab.yaml",
            "--repetitions",
            "3",
        ],
    )

    assert result.exit_code == 2, result.output
    assert "requires at least 7" in result.output


def test_kisa_retest_cli_fails_closed_when_durable_ticket_ledger_is_corrupt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    output = tmp_path / "runs"
    ledger = output / "retest-replay" / "replay-tickets.sqlite3"
    ledger.parent.mkdir(parents=True)
    ledger.parent.chmod(0o700)
    ledger.write_bytes(b"not a SQLite database")

    class FakeRetestService:
        def create_remediation_plan(self, _baseline_run: Path) -> SimpleNamespace:
            return SimpleNamespace(actions=[], path=baseline / "remediation-plan.json")

        def build_retest_contexts(
            self,
            _baseline_run: Path,
            _retest_run_path: Path,
        ) -> dict[str, object]:
            return {}

    class FakePlanner:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def plan(self, _campaign: object) -> SimpleNamespace:
            return SimpleNamespace(steps=[])

    class FakeRunner:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def run(self, *_args: object, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(
                status=RunStatus.COMPLETED,
                run_path=output / "retest-run",
            )

    class LedgerOpeningCoordinator:
        def __init__(self, **kwargs: object) -> None:
            self.ticket_authority_factory = kwargs["ticket_authority_factory"]

        async def reproduce(self, *_args: object, **_kwargs: object) -> None:
            assert callable(self.ticket_authority_factory)
            self.ticket_authority_factory()
            raise AssertionError("a corrupt durable ledger must fail during authority open")

    monkeypatch.setattr(cli, "_worker_backend", lambda _worker: object())
    monkeypatch.setattr(cli, "KISARetestService", FakeRetestService)
    monkeypatch.setattr(cli, "KISARetestPlannerRuntime", FakePlanner)
    monkeypatch.setattr(cli, "MultiAgentCampaignRunner", FakeRunner)
    monkeypatch.setattr(cli, "KISARetestReplayCoordinator", LedgerOpeningCoordinator)

    result = CliRunner().invoke(
        cli.app,
        [
            "kisa-retest",
            str(baseline),
            "examples/kisa-ai-chat-lab.yaml",
            "--output",
            str(output),
            "--worker",
            "simulated",
        ],
    )

    assert result.exit_code == 1, result.output
    assert "KISA retest execution failed" in result.output
    assert "ledger initialization failed" in result.output
