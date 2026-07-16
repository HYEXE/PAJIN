from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import pajin.cli as cli
from pajin.replay.tickets import ReplayTicketFinalizationVerifier


def _probe_ticket_ledger(
    _run_path: Path,
    *,
    tickets: ReplayTicketFinalizationVerifier,
) -> None:
    tickets.verify_finalized(
        "replay-ticket_probe",
        final_seal_root_digest="a" * 64,
        artifact_set_digest="b" * 64,
        compilation_digest="c" * 64,
        candidate_source_root_digest="d" * 64,
        replay_run_id="replay-run_probe",
    )


def test_replay_verify_cli_reports_durable_ticket_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replay_run = tmp_path / "replay-run"
    replay_run.mkdir()
    ledger = tmp_path / "replay-tickets.sqlite3"
    captured: dict[str, object] = {}

    class FakeVerifier:
        def __init__(self, path: Path) -> None:
            captured["ledger"] = path

    def load_verified(run_path: Path, *, tickets: object) -> SimpleNamespace:
        captured["run_path"] = run_path
        captured["tickets"] = tickets
        return SimpleNamespace(
            verification=SimpleNamespace(run_id="replay-run_123"),
            receipt=SimpleNamespace(
                ticket_id="replay-ticket_abc",
                candidate_source_root_digest="a" * 64,
            ),
            receipt_seal_root_digest="b" * 64,
        )

    monkeypatch.setattr(cli, "SQLiteReplayTicketFinalizationVerifier", FakeVerifier)
    monkeypatch.setattr(cli, "load_verified_replay_result", load_verified)

    result = CliRunner().invoke(
        cli.app,
        ["replay-verify", str(replay_run), "--ledger", str(ledger)],
    )

    assert result.exit_code == 0, result.output
    assert captured["ledger"] == ledger
    assert captured["run_path"] == replay_run
    assert isinstance(captured["tickets"], FakeVerifier)
    assert "VALID" in result.output
    assert "replay-run_123" in result.output
    assert "replay-ticket_abc" in result.output
    assert "b" * 64 in result.output


@pytest.mark.parametrize(
    "error",
    [
        OSError("durable replay ticket ledger does not exist"),
        sqlite3.DatabaseError("file is not a database"),
        RuntimeError("durable replay ticket schema version is unsupported"),
    ],
)
def test_replay_verify_cli_fails_closed_when_ledger_cannot_be_opened(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    replay_run = tmp_path / "replay-run"
    replay_run.mkdir()

    class RejectingVerifier:
        def __init__(self, _path: Path) -> None:
            raise error

    monkeypatch.setattr(cli, "SQLiteReplayTicketFinalizationVerifier", RejectingVerifier)

    result = CliRunner().invoke(
        cli.app,
        [
            "replay-verify",
            str(replay_run),
            "--ledger",
            str(tmp_path / "missing-or-wrong.sqlite3"),
        ],
    )

    assert result.exit_code == 1
    assert "Replay verification failed" in result.output
    assert str(error) in " ".join(result.output.split())


@pytest.mark.parametrize(
    "error",
    [
        ValueError("sealed replay receipt does not match its canonical artifacts"),
        PermissionError("finalized replay ticket does not match the sealed receipt"),
        KeyError("unknown replay execution ticket"),
    ],
)
def test_replay_verify_cli_fails_closed_on_invalid_or_tampered_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    replay_run = tmp_path / "replay-run"
    replay_run.mkdir()

    class FakeVerifier:
        def __init__(self, _path: Path) -> None:
            pass

    def reject_verification(_run_path: Path, *, tickets: object) -> None:
        assert isinstance(tickets, FakeVerifier)
        raise error

    monkeypatch.setattr(cli, "SQLiteReplayTicketFinalizationVerifier", FakeVerifier)
    monkeypatch.setattr(cli, "load_verified_replay_result", reject_verification)

    result = CliRunner().invoke(
        cli.app,
        [
            "replay-verify",
            str(replay_run),
            "--ledger",
            str(tmp_path / "replay-tickets.sqlite3"),
        ],
    )

    assert result.exit_code == 1
    assert "Replay verification failed" in result.output
    assert str(error) in " ".join(result.output.split())


def test_replay_verify_cli_reports_missing_run_as_verification_failure(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli.app,
        [
            "replay-verify",
            str(tmp_path / "missing-run"),
            "--ledger",
            str(tmp_path / "replay-tickets.sqlite3"),
        ],
    )

    assert result.exit_code == 1
    assert "Replay verification failed" in result.output
    assert "replay Run directory does not exist" in result.output


def test_replay_verify_cli_missing_ledger_never_creates_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replay_run = tmp_path / "replay-run"
    replay_run.mkdir()
    state_root = tmp_path / "missing-state"
    ledger = state_root / "replay-tickets.sqlite3"
    monkeypatch.setattr(cli, "load_verified_replay_result", _probe_ticket_ledger)

    result = CliRunner().invoke(
        cli.app,
        ["replay-verify", str(replay_run), "--ledger", str(ledger)],
    )

    assert result.exit_code == 1
    assert "Replay verification failed" in result.output
    assert not ledger.exists()
    assert not state_root.exists()


@pytest.mark.parametrize("ledger_kind", ["corrupt", "wrong-schema"])
def test_replay_verify_cli_rejects_untrusted_ledger_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ledger_kind: str,
) -> None:
    replay_run = tmp_path / "replay-run"
    replay_run.mkdir()
    ledger = tmp_path / "replay-tickets.sqlite3"
    if ledger_kind == "corrupt":
        ledger.write_bytes(b"this is not a SQLite database")
    else:
        connection = sqlite3.connect(ledger)
        try:
            connection.execute("CREATE TABLE unrelated (value TEXT NOT NULL)")
            connection.commit()
        finally:
            connection.close()
    monkeypatch.setattr(cli, "load_verified_replay_result", _probe_ticket_ledger)

    result = CliRunner().invoke(
        cli.app,
        ["replay-verify", str(replay_run), "--ledger", str(ledger)],
    )

    assert result.exit_code == 1
    assert "Replay verification failed" in result.output
