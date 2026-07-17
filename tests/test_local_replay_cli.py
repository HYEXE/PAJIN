from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import pajin.cli as cli
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignMode
from pajin.runtime.control import BudgetController, ExecutionCancellationContext
from pajin.tools.gateway import RequestRateLimitLedger

KISA_MANIFEST = Path("examples/kisa-ai-chat-lab.yaml")


def test_run_defaults_to_the_existing_local_path_without_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "source-run" / "report.md"

    class FakeLocalRunner:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def run(self, _campaign: object) -> SimpleNamespace:
            return SimpleNamespace(
                run_id="source-run",
                tool_results=[],
                findings=[],
                validation=SimpleNamespace(decisions=[]),
                report_path=report_path,
            )

    class UnexpectedReplayOrchestrator:
        def __init__(self, **_kwargs: object) -> None:
            raise AssertionError("the default Local command must not construct replay")

    monkeypatch.setattr(cli, "_worker_backend", lambda _worker: object())
    monkeypatch.setattr(cli, "LocalCampaignRunner", FakeLocalRunner)
    monkeypatch.setattr(
        cli,
        "KISALocalReplayOrchestrator",
        UnexpectedReplayOrchestrator,
    )

    result = CliRunner().invoke(
        cli.app,
        ["run", str(KISA_MANIFEST), "--output", str(tmp_path / "runs")],
    )

    assert result.exit_code == 0, result.output
    assert "Campaign completed: source-run" in result.output
    assert "Replay records" not in result.output
    assert "Report:" in result.output


def test_run_rejects_explicit_repetitions_without_kisa_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "load_manifest",
        lambda _path: (_ for _ in ()).throw(AssertionError("must fail before loading")),
    )

    result = CliRunner().invoke(
        cli.app,
        ["run", str(KISA_MANIFEST), "--repetitions", "3"],
    )

    assert result.exit_code == 2, result.output
    assert "--repetitions requires --kisa-replay" in result.output


@pytest.mark.parametrize("repetitions", ["1", "21"])
def test_run_kisa_replay_repetitions_are_bounded(
    repetitions: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "load_manifest",
        lambda _path: (_ for _ in ()).throw(AssertionError("Click must reject the value")),
    )

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            str(KISA_MANIFEST),
            "--kisa-replay",
            "--repetitions",
            repetitions,
        ],
    )

    assert result.exit_code == 2, result.output
    assert "Invalid value" in result.output


def test_run_kisa_replay_rejects_non_ai_campaign_before_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = load_manifest(KISA_MANIFEST)
    non_ai_campaign = campaign.model_copy(
        update={"spec": campaign.spec.model_copy(update={"mode": CampaignMode.BUG_BOUNTY})}
    )
    output = tmp_path / "runs"

    monkeypatch.setattr(cli, "load_manifest", lambda _path: non_ai_campaign)
    monkeypatch.setattr(
        cli,
        "_worker_backend",
        lambda _worker: (_ for _ in ()).throw(AssertionError("must fail before worker setup")),
    )

    result = CliRunner().invoke(
        cli.app,
        ["run", str(KISA_MANIFEST), "--kisa-replay", "--output", str(output)],
    )

    assert result.exit_code == 2, result.output
    assert "requires mode: ai-redteam" in result.output
    assert not output.exists()


def test_run_kisa_replay_reserves_source_and_replay_budget_before_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "runs"
    monkeypatch.setattr(
        cli,
        "_worker_backend",
        lambda _worker: (_ for _ in ()).throw(AssertionError("must fail before worker setup")),
    )

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            str(KISA_MANIFEST),
            "--kisa-replay",
            "--repetitions",
            "3",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2, result.output
    assert "requires at least 18" in result.output
    assert not output.exists()


def test_run_kisa_replay_uses_shared_controls_and_stable_sqlite_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "runs"
    report_path = output / "source-run" / "validation" / "v1" / "report.md"
    observed: dict[str, object] = {}

    class FakeOrchestrator:
        def __init__(self, **kwargs: object) -> None:
            observed.update(kwargs)
            authority_factory = kwargs["ticket_authority_factory"]
            assert callable(authority_factory)
            authority = authority_factory()
            observed["authority_path"] = authority.path

        async def run(self, _campaign: object, **kwargs: object) -> SimpleNamespace:
            observed.update({f"run_{key}": value for key, value in kwargs.items()})
            return SimpleNamespace(
                outcome=SimpleNamespace(
                    run_id="source-run",
                    tool_results=[],
                    findings=[object(), object()],
                    report_path=report_path,
                ),
                batch=SimpleNamespace(
                    records=tuple(SimpleNamespace(execution_status="succeeded") for _ in range(3))
                ),
            )

    monkeypatch.setattr(cli, "_worker_backend", lambda _worker: object())
    monkeypatch.setattr(cli, "KISALocalReplayOrchestrator", FakeOrchestrator)

    result = CliRunner().invoke(
        cli.app,
        ["run", str(KISA_MANIFEST), "--kisa-replay", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    assert isinstance(observed["run_budget"], BudgetController)
    assert isinstance(observed["run_rate_limits"], RequestRateLimitLedger)
    assert isinstance(observed["run_cancellation"], ExecutionCancellationContext)
    assert (
        observed["authority_path"] == (output / "local-replay" / "replay-tickets.sqlite3").resolve()
    )
    assert "Confirmed findings: 2" in result.output
    assert "Replay records: 3" in result.output
    assert "Final report:" in result.output
    assert "validation/v1/report.md" in result.output.replace("\n", "")


def test_run_kisa_replay_fails_closed_on_typed_replay_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailedReplayOrchestrator:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def run(self, _campaign: object, **_kwargs: object) -> SimpleNamespace:
            return SimpleNamespace(
                outcome=SimpleNamespace(
                    run_id="source-run",
                    tool_results=[],
                    findings=[],
                    report_path=tmp_path / "source-run" / "report.md",
                ),
                batch=SimpleNamespace(records=(SimpleNamespace(execution_status="failed"),)),
            )

    monkeypatch.setattr(cli, "_worker_backend", lambda _worker: object())
    monkeypatch.setattr(cli, "KISALocalReplayOrchestrator", FailedReplayOrchestrator)

    result = CliRunner().invoke(
        cli.app,
        [
            "run",
            str(KISA_MANIFEST),
            "--kisa-replay",
            "--output",
            str(tmp_path / "runs"),
        ],
    )

    assert result.exit_code == 1, result.output
    assert "one or more replay records did not succeed" in result.output
    assert "Campaign completed" not in result.output
    assert "Final report" not in result.output


def test_run_kisa_replay_fails_closed_on_corrupt_sqlite_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "runs"
    ledger = output / "local-replay" / "replay-tickets.sqlite3"
    ledger.parent.mkdir(parents=True)
    ledger.write_bytes(b"not a SQLite database")

    class LedgerOpeningOrchestrator:
        def __init__(self, **kwargs: object) -> None:
            self._authority_factory = kwargs["ticket_authority_factory"]

        async def run(self, _campaign: object, **_kwargs: object) -> None:
            assert callable(self._authority_factory)
            self._authority_factory()
            raise AssertionError("a corrupt SQLite ledger must fail while opening")

    monkeypatch.setattr(cli, "_worker_backend", lambda _worker: object())
    monkeypatch.setattr(cli, "KISALocalReplayOrchestrator", LedgerOpeningOrchestrator)

    result = CliRunner().invoke(
        cli.app,
        ["run", str(KISA_MANIFEST), "--kisa-replay", "--output", str(output)],
    )

    assert result.exit_code == 1, result.output
    assert "Local KISA replay failed" in result.output
    assert "ledger initialization failed" in result.output
    assert "Campaign completed" not in result.output
    assert "Final report" not in result.output
