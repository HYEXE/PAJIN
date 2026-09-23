"""Offline Codex JSONL admission and conservative next-turn usage accounting.

This module cannot dispatch a model or authorize hosted transfer. The journal
retains bounded terminal streams and receipts locally; uncertain started turns
are never freed.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final, Literal
from uuid import uuid4

from pajin.agentic.codex_routing import (
    CodexAdvisoryRoutingPlan,
    CodexAdvisoryStage,
)
from pajin.runtime.safe_files import parse_strict_json_bytes

_MAX_EVENTS_BYTES: Final = 2 * 1024 * 1024
_MAX_MESSAGE_BYTES: Final = 128 * 1024
_DIGEST_RE: Final = re.compile(r"^[a-f0-9]{64}$")
_NON_TOOL_ITEMS: Final = frozenset({"agent_message", "reasoning"})
_DISABLED_CODE_MODE_DIAGNOSTIC: Final = (
    "Code Mode is unavailable because code-mode host is disabled. "
    "Code mode will fail closed; enable `features.code_mode_host` and install "
    "`codex-code-mode-host`."
)


class CodexAdvisoryUsageError(ValueError):
    """A Codex turn, its usage, or its conservative accounting is inadmissible."""


@dataclass(frozen=True, slots=True)
class CodexTurnUsage:
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    cache_write_input_tokens: int = 0
    reasoning_output_tokens: int = 0

    def __post_init__(self) -> None:
        if (
            type(self.input_tokens) is not int
            or type(self.cached_input_tokens) is not int
            or type(self.output_tokens) is not int
            or type(self.cache_write_input_tokens) is not int
            or type(self.reasoning_output_tokens) is not int
            or self.input_tokens < 1
            or not 0 <= self.cached_input_tokens <= self.input_tokens
            or not 0 <= self.cache_write_input_tokens <= self.input_tokens
            or self.output_tokens < 0
            or not 0 <= self.reasoning_output_tokens <= self.output_tokens
            or self.input_tokens > 1_000_000_000
            or self.output_tokens > 1_000_000_000
        ):
            raise CodexAdvisoryUsageError("Codex turn usage is incomplete or inconsistent")

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True, slots=True)
class CodexAdvisoryTurn:
    thread_id: str
    message: str
    usage: CodexTurnUsage


def _parse_event(line: bytes) -> dict[str, object]:
    try:
        event = parse_strict_json_bytes(
            line,
            label="Codex exec event",
            max_bytes=_MAX_MESSAGE_BYTES + 4096,
            max_depth=8,
            max_nodes=256,
        )
    except (TypeError, ValueError) as exc:
        raise CodexAdvisoryUsageError("Codex event stream has invalid JSON") from exc
    if type(event) is not dict or type(event.get("type")) is not str:
        raise CodexAdvisoryUsageError("Codex event has no exact type")
    return event


def _read_item(event: dict[str, object], message: str | None) -> str | None:
    item = event.get("item")
    if (
        type(item) is not dict
        or type(item.get("type")) is not str
        or item["type"] not in _NON_TOOL_ITEMS
    ):
        raise CodexAdvisoryUsageError("Codex turn contains a tool or unknown item")
    if event["type"] != "item.completed" or item["type"] != "agent_message":
        return message
    value = item.get("text")
    if message is not None or type(value) is not str or not value:
        raise CodexAdvisoryUsageError("Codex final message is absent or ambiguous")
    try:
        message_bytes = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CodexAdvisoryUsageError("Codex final message is not valid UTF-8") from exc
    if len(message_bytes) > _MAX_MESSAGE_BYTES:
        raise CodexAdvisoryUsageError("Codex final message exceeds its byte limit")
    return value


def _read_usage(event: dict[str, object]) -> CodexTurnUsage:
    raw_usage = event.get("usage")
    required = {
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
    }
    optional = {"cache_write_input_tokens", "reasoning_output_tokens"}
    if (
        type(raw_usage) is not dict
        or not required <= set(raw_usage)
        or not set(raw_usage) <= required | optional
    ):
        raise CodexAdvisoryUsageError("Codex completed turn has no exact usage")
    return CodexTurnUsage(
        input_tokens=raw_usage["input_tokens"],
        cached_input_tokens=raw_usage["cached_input_tokens"],
        output_tokens=raw_usage["output_tokens"],
        cache_write_input_tokens=raw_usage.get("cache_write_input_tokens", 0),
        reasoning_output_tokens=raw_usage.get("reasoning_output_tokens", 0),
    )


def parse_codex_exec_jsonl(content: bytes) -> CodexAdvisoryTurn:
    """Admit one completed no-tool turn from bounded Codex ``exec --json`` events."""

    if type(content) is not bytes or not content or len(content) > _MAX_EVENTS_BYTES:
        raise CodexAdvisoryUsageError("Codex event stream is absent or exceeds its byte limit")
    lines = content.splitlines()
    if not lines or any(not line for line in lines):
        raise CodexAdvisoryUsageError("Codex event stream contains an empty event")
    thread_id: str | None = None
    started = False
    completed = False
    disabled_code_mode_diagnostic_seen = False
    message: str | None = None
    usage: CodexTurnUsage | None = None
    for index, line in enumerate(lines):
        event = _parse_event(line)
        event_type = event["type"]
        item = event.get("item")
        if completed:
            raise CodexAdvisoryUsageError("Codex event follows terminal completion")
        if event_type == "thread.started" and index == 0:
            value = event.get("thread_id")
            if type(value) is not str or not value or len(value) > 200:
                raise CodexAdvisoryUsageError("Codex thread identifier is invalid")
            thread_id = value
        elif (
            event_type == "item.completed"
            and thread_id is not None
            and not started
            and not disabled_code_mode_diagnostic_seen
            and type(item) is dict
            and item.get("type") == "error"
            and item.get("message") == _DISABLED_CODE_MODE_DIAGNOSTIC
        ):
            # Codex 0.156.1 reports its disabled Code Mode host before turn start.
            # This exact diagnostic is not a model tool event or a successful tool call.
            disabled_code_mode_diagnostic_seen = True
        elif event_type == "turn.started" and thread_id is not None and not started:
            started = True
        elif event_type in {"item.started", "item.updated", "item.completed"} and started:
            message = _read_item(event, message)
        elif event_type == "turn.completed" and started:
            usage = _read_usage(event)
            completed = True
        else:
            raise CodexAdvisoryUsageError("Codex event order or type is not admissible")
    if thread_id is None or not started or not completed or message is None or usage is None:
        raise CodexAdvisoryUsageError("Codex turn lacks a final message or terminal usage")
    return CodexAdvisoryTurn(thread_id=thread_id, message=message, usage=usage)


CodexAttemptState = Literal["reserved", "started-uncertain", "succeeded", "failed", "cancelled"]


@dataclass(frozen=True, slots=True)
class CodexAdvisoryAttempt:
    attempt_id: str
    stage: CodexAdvisoryStage
    model_id: str
    input_digest: str
    planned_tokens: int
    state: CodexAttemptState
    observed_tokens: int | None
    output_digest: str | None


class CodexAdvisoryUsageJournal:
    """SQLite-backed soft budget: reserve before, debit observed usage after a turn."""

    def __init__(
        self,
        path: Path,
        *,
        plan: CodexAdvisoryRoutingPlan,
        max_total_tokens: int,
    ) -> None:
        self.path = path
        self.plan = CodexAdvisoryRoutingPlan.model_validate(plan.model_dump(mode="json"))
        if (
            type(max_total_tokens) is not int
            or max_total_tokens < self.plan.max_task_tokens
            or max_total_tokens > 1_000_000_000
        ):
            raise CodexAdvisoryUsageError("Codex journal token budget is below one planned turn")
        self.max_total_tokens = max_total_tokens
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS policy ("
                "id INTEGER PRIMARY KEY CHECK (id = 1), "
                "plan_digest TEXT NOT NULL, max_total_tokens INTEGER NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS attempts ("
                "attempt_id TEXT PRIMARY KEY, stage TEXT NOT NULL, model_id TEXT NOT NULL, "
                "input_digest TEXT NOT NULL, planned_tokens INTEGER NOT NULL "
                "CHECK (planned_tokens > 0), "
                "state TEXT NOT NULL CHECK (state IN ('reserved', 'started-uncertain', "
                "'succeeded', 'failed', 'cancelled')), "
                "observed_tokens INTEGER CHECK (observed_tokens >= 0), output_digest TEXT)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS terminal_receipts ("
                "attempt_id TEXT PRIMARY KEY, receipt_sha256 TEXT NOT NULL, "
                "receipt_bytes BLOB NOT NULL, event_sha256 TEXT NOT NULL, "
                "event_bytes BLOB NOT NULL, stderr_sha256 TEXT NOT NULL, "
                "stderr_bytes BLOB NOT NULL)"
            )
            row = connection.execute(
                "SELECT plan_digest, max_total_tokens FROM policy WHERE id = 1"
            ).fetchone()
            policy = (self.plan.plan_digest, self.max_total_tokens)
            if row is None:
                connection.execute(
                    "INSERT INTO policy VALUES (1, ?, ?)",
                    policy,
                )
            elif row != policy:
                raise CodexAdvisoryUsageError("Codex journal policy differs on reopen")

    @staticmethod
    def _attempt(connection: sqlite3.Connection, attempt_id: str) -> CodexAdvisoryAttempt:
        row = connection.execute(
            "SELECT attempt_id, stage, model_id, input_digest, planned_tokens, "
            "state, observed_tokens, output_digest FROM attempts WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if row is None:
            raise CodexAdvisoryUsageError("Codex attempt is unknown")
        return CodexAdvisoryAttempt(
            attempt_id=row[0],
            stage=CodexAdvisoryStage(row[1]),
            model_id=row[2],
            input_digest=row[3],
            planned_tokens=row[4],
            state=row[5],
            observed_tokens=row[6],
            output_digest=row[7],
        )

    def get(self, attempt_id: str) -> CodexAdvisoryAttempt:
        with self._connection() as connection:
            return self._attempt(connection, attempt_id)

    def terminal_receipt(self, attempt_id: str) -> bytes | None:
        """Return the exact retained receipt, rejecting a changed database payload."""

        with self._connection() as connection:
            self._attempt(connection, attempt_id)
            row = connection.execute(
                "SELECT receipt_sha256, receipt_bytes FROM terminal_receipts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if row is None:
                return None
            receipt_bytes = bytes(row[1])
            if sha256(receipt_bytes).hexdigest() != row[0]:
                raise CodexAdvisoryUsageError("Codex terminal receipt differs from its digest")
            return receipt_bytes

    def terminal_streams(self, attempt_id: str) -> tuple[bytes, bytes] | None:
        """Return exact retained JSONL and stderr for local-only audit."""

        with self._connection() as connection:
            self._attempt(connection, attempt_id)
            row = connection.execute(
                "SELECT event_sha256, event_bytes, stderr_sha256, stderr_bytes "
                "FROM terminal_receipts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if row is None:
                return None
            events, stderr = bytes(row[1]), bytes(row[3])
            if sha256(events).hexdigest() != row[0] or sha256(stderr).hexdigest() != row[2]:
                raise CodexAdvisoryUsageError("Codex terminal streams differ from their digests")
            return events, stderr

    def charged_tokens(self) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COALESCE(SUM(CASE WHEN state = 'cancelled' THEN 0 "
                "ELSE COALESCE(observed_tokens, planned_tokens) END), 0) FROM attempts"
            ).fetchone()
            assert row is not None
            return int(row[0])

    def reserve(self, *, stage: CodexAdvisoryStage, input_digest: str) -> CodexAdvisoryAttempt:
        if (
            type(stage) is not CodexAdvisoryStage
            or type(input_digest) is not str
            or _DIGEST_RE.fullmatch(input_digest) is None
        ):
            raise CodexAdvisoryUsageError("Codex reservation requires an exact stage and digest")
        route = next(route for route in self.plan.routes if route.stage == stage)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            reused = connection.execute(
                "SELECT 1 FROM attempts WHERE stage = ? AND input_digest = ? "
                "AND state != 'cancelled' LIMIT 1",
                (stage.value, input_digest),
            ).fetchone()
            if reused is not None:
                raise CodexAdvisoryUsageError(
                    "Codex exact stage and input already used one attempted dispatch"
                )
            unresolved = connection.execute(
                "SELECT 1 FROM attempts WHERE state = 'started-uncertain' "
                "OR (state = 'failed' AND observed_tokens IS NULL) LIMIT 1"
            ).fetchone()
            if unresolved is not None:
                raise CodexAdvisoryUsageError("Codex unresolved usage blocks every later turn")
            row = connection.execute(
                "SELECT COALESCE(SUM(CASE WHEN state = 'cancelled' THEN 0 "
                "ELSE COALESCE(observed_tokens, planned_tokens) END), 0) FROM attempts"
            ).fetchone()
            assert row is not None
            if int(row[0]) + route.max_task_tokens > self.max_total_tokens:
                raise CodexAdvisoryUsageError(
                    "Codex next turn exceeds its observed/reserved budget"
                )
            attempt_id = uuid4().hex
            connection.execute(
                "INSERT INTO attempts VALUES (?, ?, ?, ?, ?, 'reserved', NULL, NULL)",
                (attempt_id, stage.value, route.model_id, input_digest, route.max_task_tokens),
            )
            return self._attempt(connection, attempt_id)

    def mark_started(self, attempt_id: str) -> CodexAdvisoryAttempt:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                "UPDATE attempts SET state = 'started-uncertain' "
                "WHERE attempt_id = ? AND state = 'reserved'",
                (attempt_id,),
            )
            if result.rowcount != 1:
                raise CodexAdvisoryUsageError("Codex attempt cannot start or redispatch")
            return self._attempt(connection, attempt_id)

    def cancel_before_dispatch(self, attempt_id: str) -> CodexAdvisoryAttempt:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                "UPDATE attempts SET state = 'cancelled' "
                "WHERE attempt_id = ? AND state = 'reserved'",
                (attempt_id,),
            )
            if result.rowcount != 1:
                raise CodexAdvisoryUsageError("Only an undispatched Codex attempt may be cancelled")
            return self._attempt(connection, attempt_id)

    def finalize(
        self,
        attempt_id: str,
        *,
        usage: CodexTurnUsage | None,
        output_digest: str | None,
        success: bool,
        receipt_bytes: bytes | None = None,
        event_bytes: bytes | None = None,
        stderr_bytes: bytes | None = None,
    ) -> CodexAdvisoryAttempt:
        if type(success) is not bool or (success and (usage is None or output_digest is None)):
            raise CodexAdvisoryUsageError("Successful Codex turn requires usage and output digest")
        if usage is not None and type(usage) is not CodexTurnUsage:
            raise CodexAdvisoryUsageError("Codex usage must be an exact admitted record")
        if output_digest is not None and (
            type(output_digest) is not str or _DIGEST_RE.fullmatch(output_digest) is None
        ):
            raise CodexAdvisoryUsageError("Codex output digest is invalid")
        if receipt_bytes is not None and (
            type(receipt_bytes) is not bytes or not receipt_bytes or len(receipt_bytes) > 32 * 1024
        ):
            raise CodexAdvisoryUsageError("Codex terminal receipt is absent or oversized")
        if (receipt_bytes is None and (event_bytes is not None or stderr_bytes is not None)) or (
            receipt_bytes is not None and (event_bytes is None or stderr_bytes is None)
        ):
            raise CodexAdvisoryUsageError(
                "Codex terminal receipt and streams must be stored together"
            )
        if receipt_bytes is not None and (
            type(event_bytes) is not bytes
            or len(event_bytes) > _MAX_EVENTS_BYTES
            or type(stderr_bytes) is not bytes
            or len(stderr_bytes) > 64 * 1024
        ):
            raise CodexAdvisoryUsageError("Codex terminal streams exceed their byte limits")
        state = "succeeded" if success else "failed"
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                "UPDATE attempts SET state = ?, observed_tokens = ?, output_digest = ? "
                "WHERE attempt_id = ? AND state = 'started-uncertain'",
                (
                    state,
                    usage.total_tokens if usage is not None else None,
                    output_digest,
                    attempt_id,
                ),
            )
            if result.rowcount != 1:
                raise CodexAdvisoryUsageError(
                    "Codex attempt is already terminal or was not started"
                )
            if receipt_bytes is not None:
                assert event_bytes is not None and stderr_bytes is not None
                connection.execute(
                    "INSERT INTO terminal_receipts VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        attempt_id,
                        sha256(receipt_bytes).hexdigest(),
                        receipt_bytes,
                        sha256(event_bytes).hexdigest(),
                        event_bytes,
                        sha256(stderr_bytes).hexdigest(),
                        stderr_bytes,
                    ),
                )
            return self._attempt(connection, attempt_id)
