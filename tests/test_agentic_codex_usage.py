"""Offline checks for Codex turn admission and observed-usage reservations."""

from __future__ import annotations

import json
import sqlite3
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.agentic.codex_routing import (
    CodexAdvisoryStage,
    code_owned_codex_advisory_routing_plan,
)
from pajin.agentic.codex_usage import (
    CodexAdvisoryUsageError,
    CodexAdvisoryUsageJournal,
    CodexTurnUsage,
    parse_codex_exec_jsonl,
)

_DIGEST = sha256(b"target-neutral-input").hexdigest()


def _events(*, item_type: str = "agent_message", usage: object | None = None) -> bytes:
    if usage is None:
        usage = {"input_tokens": 21000, "cached_input_tokens": 11000, "output_tokens": 20}
    events = [
        {"type": "thread.started", "thread_id": "thread-example"},
        {"type": "turn.started"},
        {"type": "item.started", "item": {"id": "item-1", "type": item_type}},
        {
            "type": "item.completed",
            "item": {"id": "item-1", "type": item_type, "text": "{}"},
        },
        {"type": "turn.completed", "usage": usage},
    ]
    return b"\n".join(json.dumps(event).encode() for event in events) + b"\n"


def test_completed_no_tool_turn_admits_observed_cli_usage() -> None:
    result = parse_codex_exec_jsonl(
        _events(
            usage={
                "input_tokens": 17009,
                "cached_input_tokens": 0,
                "cache_write_input_tokens": 0,
                "output_tokens": 150,
                "reasoning_output_tokens": 141,
            }
        )
    )

    assert result.thread_id == "thread-example"
    assert result.message == "{}"
    assert result.usage.total_tokens == 17159
    assert result.usage.reasoning_output_tokens == 141


def test_exact_disabled_code_mode_diagnostic_before_turn_is_admissible() -> None:
    diagnostic = {
        "type": "item.completed",
        "item": {
            "type": "error",
            "message": (
                "Code Mode is unavailable because code-mode host is disabled. "
                "Code mode will fail closed; enable `features.code_mode_host` and install "
                "`codex-code-mode-host`."
            ),
        },
    }
    events = _events().replace(
        b'{"type": "turn.started"}',
        json.dumps(diagnostic).encode() + b'\n{"type": "turn.started"}',
    )
    assert parse_codex_exec_jsonl(events).message == "{}"
    with pytest.raises(CodexAdvisoryUsageError):
        parse_codex_exec_jsonl(
            events.replace(
                json.dumps(diagnostic).encode() + b"\n",
                (json.dumps(diagnostic).encode() + b"\n") * 2,
            )
        )


@pytest.mark.parametrize("item_type", ["command_execution", "web_search", "file_change"])
def test_tool_items_fail_closed(item_type: str) -> None:
    with pytest.raises(CodexAdvisoryUsageError, match="tool or unknown"):
        parse_codex_exec_jsonl(_events(item_type=item_type))


@pytest.mark.parametrize(
    "usage",
    [
        {},
        {"input_tokens": True, "cached_input_tokens": 0, "output_tokens": 1},
        {"input_tokens": 1, "cached_input_tokens": 2, "output_tokens": 1},
        {"input_tokens": 1, "cached_input_tokens": 0, "output_tokens": -1},
        {
            "input_tokens": 1,
            "cached_input_tokens": 0,
            "output_tokens": 1,
            "reasoning_output_tokens": 2,
        },
    ],
)
def test_missing_or_inconsistent_usage_fails_closed(usage: object) -> None:
    with pytest.raises(CodexAdvisoryUsageError):
        parse_codex_exec_jsonl(_events(usage=usage))


def test_duplicate_json_key_and_second_terminal_event_fail_closed() -> None:
    duplicate = _events().replace(
        b'"input_tokens": 21000', b'"input_tokens": 1, "input_tokens": 21000'
    )
    with pytest.raises(CodexAdvisoryUsageError):
        parse_codex_exec_jsonl(duplicate)
    with pytest.raises(CodexAdvisoryUsageError, match="follows terminal"):
        parse_codex_exec_jsonl(_events() + b'{"type":"turn.completed"}\n')


def test_unexpected_error_item_and_second_agent_message_fail_closed() -> None:
    error_item = b'{"type":"item.completed","item":{"type":"error"}}\n'
    with pytest.raises(CodexAdvisoryUsageError):
        parse_codex_exec_jsonl(_events().replace(b'{"type": "turn.started"}\n', error_item))
    duplicate_message = (
        b'{"type":"item.completed","item":{"type":"agent_message","text":"again"}}\n'
    )
    with pytest.raises(CodexAdvisoryUsageError, match="ambiguous"):
        parse_codex_exec_jsonl(
            _events().replace(
                b'{"type": "turn.completed"', duplicate_message + b'{"type": "turn.completed"'
            )
        )


def _journal(path: Path, *, max_total_tokens: int = 100) -> CodexAdvisoryUsageJournal:
    return CodexAdvisoryUsageJournal(
        path,
        plan=code_owned_codex_advisory_routing_plan(max_task_tokens=50),
        max_total_tokens=max_total_tokens,
    )


def test_started_turn_is_durable_reserved_and_cannot_redispatch(tmp_path: Path) -> None:
    path = tmp_path / "codex-usage.sqlite"
    journal = _journal(path)
    attempt = journal.reserve(stage=CodexAdvisoryStage.RECONNAISSANCE, input_digest=_DIGEST)
    assert attempt.model_id == "gpt-6-luna"
    started = journal.mark_started(attempt.attempt_id)
    assert started.state == "started-uncertain"

    reopened = _journal(path)
    assert reopened.get(attempt.attempt_id) == started
    assert reopened.charged_tokens() == 50
    with pytest.raises(CodexAdvisoryUsageError, match="redispatch"):
        reopened.mark_started(attempt.attempt_id)
    with pytest.raises(CodexAdvisoryUsageError, match="undispatched"):
        reopened.cancel_before_dispatch(attempt.attempt_id)
    with pytest.raises(CodexAdvisoryUsageError, match="unresolved usage"):
        reopened.reserve(stage=CodexAdvisoryStage.REPORT_DRAFT, input_digest=_DIGEST)


def test_observed_usage_limits_the_next_turn_and_records_overrun(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "codex-usage.sqlite")
    first = journal.reserve(stage=CodexAdvisoryStage.RECONNAISSANCE, input_digest=_DIGEST)
    journal.mark_started(first.attempt_id)
    closed = journal.finalize(
        first.attempt_id,
        usage=CodexTurnUsage(70, 20, 10),
        output_digest=sha256(b"proposal").hexdigest(),
        success=True,
    )
    assert closed.state == "succeeded"
    assert closed.observed_tokens == 80
    assert journal.charged_tokens() == 80
    with pytest.raises(CodexAdvisoryUsageError, match="budget"):
        journal.reserve(stage=CodexAdvisoryStage.PENETRATION_REVIEW, input_digest=_DIGEST)
    with pytest.raises(CodexAdvisoryUsageError, match="already terminal"):
        journal.finalize(first.attempt_id, usage=None, output_digest=None, success=False)


def test_exact_stage_input_cannot_be_reserved_after_a_dispatch(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "codex-usage.sqlite")
    first = journal.reserve(stage=CodexAdvisoryStage.RECONNAISSANCE, input_digest=_DIGEST)
    journal.mark_started(first.attempt_id)
    journal.finalize(
        first.attempt_id,
        usage=CodexTurnUsage(20, 0, 5),
        output_digest=sha256(b"proposal").hexdigest(),
        success=True,
    )
    with pytest.raises(CodexAdvisoryUsageError, match="already used"):
        journal.reserve(stage=CodexAdvisoryStage.RECONNAISSANCE, input_digest=_DIGEST)


def test_uncertain_failure_blocks_later_calls_and_pre_dispatch_cancel_releases_budget(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "failed.sqlite")
    first = journal.reserve(stage=CodexAdvisoryStage.RECONNAISSANCE, input_digest=_DIGEST)
    journal.mark_started(first.attempt_id)
    journal.finalize(first.attempt_id, usage=None, output_digest=None, success=False)
    assert journal.charged_tokens() == 50
    with pytest.raises(CodexAdvisoryUsageError, match="unresolved usage"):
        journal.reserve(stage=CodexAdvisoryStage.REPORT_DRAFT, input_digest=_DIGEST)

    cancellable = _journal(tmp_path / "cancelled.sqlite")
    second = cancellable.reserve(stage=CodexAdvisoryStage.REPORT_DRAFT, input_digest=_DIGEST)
    assert second.model_id == "gpt-6-sol"
    cancellable.cancel_before_dispatch(second.attempt_id)
    assert cancellable.charged_tokens() == 0


def test_policy_change_on_reopen_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "codex-usage.sqlite"
    _journal(path)
    with pytest.raises(CodexAdvisoryUsageError, match="differs on reopen"):
        _journal(path, max_total_tokens=101)


def test_terminal_receipt_and_streams_are_retained_and_digest_checked(tmp_path: Path) -> None:
    path = tmp_path / "codex-usage.sqlite"
    journal = _journal(path)
    attempt = journal.reserve(stage=CodexAdvisoryStage.RECONNAISSANCE, input_digest=_DIGEST)
    journal.mark_started(attempt.attempt_id)
    journal.finalize(
        attempt.attempt_id,
        usage=CodexTurnUsage(20, 0, 5),
        output_digest=sha256(b"proposal").hexdigest(),
        success=True,
        receipt_bytes=b'{"terminalState":"succeeded"}',
        event_bytes=b'{"type":"turn.completed"}\n',
        stderr_bytes=b"",
    )
    reopened = _journal(path)
    assert reopened.terminal_receipt(attempt.attempt_id) == b'{"terminalState":"succeeded"}'
    assert reopened.terminal_streams(attempt.attempt_id) == (
        b'{"type":"turn.completed"}\n',
        b"",
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE terminal_receipts SET event_bytes = ? WHERE attempt_id = ?",
            (b"changed", attempt.attempt_id),
        )
    with pytest.raises(CodexAdvisoryUsageError, match="differ"):
        reopened.terminal_streams(attempt.attempt_id)
