"""Durable single-host claim journal for one bound Supervisor invocation."""

from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunStore, validate_run_artifact_path
from pajin.supervision.checkpoint_scheduler import (
    SupervisorCheckpointSchedule,
    SupervisorCheckpointSchedulePublication,
)

SUPERVISOR_INVOCATION_INTENT_API_VERSION: Literal[
    "pajin.dev/supervisor-invocation-intent/v1alpha1"
] = "pajin.dev/supervisor-invocation-intent/v1alpha1"
SUPERVISOR_INVOCATION_JOURNAL_ENTRY_API_VERSION: Literal[
    "pajin.dev/supervisor-invocation-journal-entry/v1alpha1"
] = "pajin.dev/supervisor-invocation-journal-entry/v1alpha1"

_SCHEMA_VERSION = 1
_APPLICATION_ID = 0x50414A53  # ASCII "PAJS"
_BUSY_TIMEOUT_MS = 30_000
_MAX_INTENT_BYTES = 512 * 1024
_SCHEDULE_ARTIFACT_PATH = "supervision/supervisor-checkpoint-schedule.json"
_RECEIPT_ARTIFACT_PATH = "supervision/supervisor-invocation-receipt.json"
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class SupervisorInvocationJournalError(RuntimeError):
    """Raised when the durable Supervisor invocation claim fails closed."""


class SupervisorInvocationJournalState(StrEnum):
    """Closed lifecycle for a request that must never be automatically redispatched."""

    INTENT_RECORDED = "intent-recorded"
    DISPATCH_STARTED_OUTCOME_UNKNOWN = "dispatch-started-outcome-unknown"
    TERMINAL_SUCCESS = "terminal-success"


class SupervisorInvocationIntent(StrictModel):
    """Content-addressed immutable binding for one sealed checkpoint invocation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/supervisor-invocation-intent/v1alpha1"] = Field(
        default=SUPERVISOR_INVOCATION_INTENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SupervisorInvocationIntent"] = "SupervisorInvocationIntent"
    intent_id: str = Field(default="", alias="intentId", max_length=110)
    intent_digest: str = Field(
        default="",
        alias="intentDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    request_id: str = Field(
        alias="requestId",
        pattern=r"^supervisor_[a-f0-9]{64}$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    checkpoint_key: _Sha256 = Field(alias="checkpointKey")
    schedule_id: str = Field(alias="scheduleId", min_length=1, max_length=110)
    schedule_digest: _Sha256 = Field(alias="scheduleDigest")
    schedule_run_id: str = Field(alias="scheduleRunId", pattern=_RUN_ID_PATTERN)
    schedule_root_digest: _Sha256 = Field(alias="scheduleRootDigest")
    schedule_artifact_path: Literal["supervision/supervisor-checkpoint-schedule.json"] = Field(
        default="supervision/supervisor-checkpoint-schedule.json",
        alias="scheduleArtifactPath",
    )
    schedule_artifact_sha256: _Sha256 = Field(alias="scheduleArtifactSha256")
    planned_call_index: int = Field(alias="plannedCallIndex", ge=1, le=32)
    request_binding_id: str = Field(
        alias="requestBindingId",
        min_length=1,
        max_length=110,
    )
    request_binding_digest: _Sha256 = Field(alias="requestBindingDigest")
    dedicated_budget_policy_id: str = Field(
        alias="dedicatedBudgetPolicyId",
        min_length=1,
        max_length=110,
    )
    dedicated_budget_policy_digest: _Sha256 = Field(alias="dedicatedBudgetPolicyDigest")
    budget_scope: Literal["campaign-and-dedicated"] = Field(
        default="campaign-and-dedicated",
        alias="budgetScope",
    )
    planned_run_id: str = Field(alias="plannedRunId", pattern=_RUN_ID_PATTERN)
    receipt_path: Literal["supervision/supervisor-invocation-receipt.json"] = Field(
        default="supervision/supervisor-invocation-receipt.json",
        alias="receiptPath",
    )
    recorded_at: datetime = Field(alias="recordedAt")
    coordination_state: Literal["claimed-not-execution-authority"] = Field(
        default="claimed-not-execution-authority",
        alias="coordinationState",
    )
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    task_created: Literal[False] = Field(default=False, alias="taskCreated")
    plan_mutated: Literal[False] = Field(default=False, alias="planMutated")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )
    activation_eligible: Literal[False] = Field(default=False, alias="activationEligible")

    @field_validator("planned_call_index", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Supervisor invocation ordinal must be a JSON integer")
        return value

    @field_validator(
        "automatic_redispatch_authorized",
        "task_created",
        "plan_mutated",
        "scope_expansion_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "activation_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Supervisor invocation authority markers must be false")
        return value

    @field_validator("recorded_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _aware_utc(value, "recorded_at")

    @model_validator(mode="after")
    def bind_intent(self) -> Self:
        if validate_run_artifact_path(self.schedule_artifact_path) != self.schedule_artifact_path:
            raise ValueError("Supervisor schedule artifact path differs")
        if validate_run_artifact_path(self.receipt_path) != self.receipt_path:
            raise ValueError("Supervisor receipt artifact path differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"intent_id", "intent_digest"},
        )
        digest = _digest("pajin.supervision.invocation-intent/v1", material)
        intent_id = f"supervisor-invocation-intent:{digest}"
        if self.intent_digest and self.intent_digest != digest:
            raise ValueError("Supervisor Invocation Intent Digest differs")
        if self.intent_id and self.intent_id != intent_id:
            raise ValueError("Supervisor Invocation Intent ID differs")
        object.__setattr__(self, "intent_digest", digest)
        object.__setattr__(self, "intent_id", intent_id)
        _intent_bytes(self)
        return self

    @property
    def stable_request_id(self) -> str:
        """Compatibility name used by the invocation runtime."""

        return self.request_id

    @property
    def provider_run_id(self) -> str:
        """Return the preclaimed RunStore identity for Provider evidence and receipt."""

        return self.planned_run_id


class SupervisorInvocationJournalEntry(StrictModel):
    """Verified journal head for one immutable invocation intent."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/supervisor-invocation-journal-entry/v1alpha1"] = Field(
        default=SUPERVISOR_INVOCATION_JOURNAL_ENTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SupervisorInvocationJournalEntry"] = "SupervisorInvocationJournalEntry"
    intent: SupervisorInvocationIntent
    state: SupervisorInvocationJournalState
    state_digest: str = Field(
        default="",
        alias="stateDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    dispatch_started_at: datetime | None = Field(
        default=None,
        alias="dispatchStartedAt",
    )
    terminal_at: datetime | None = Field(default=None, alias="terminalAt")
    final_root_digest: _Sha256 | None = Field(default=None, alias="finalRootDigest")
    receipt_path: str | None = Field(default=None, alias="receiptPath")
    receipt_sha256: _Sha256 | None = Field(default=None, alias="receiptSha256")
    dispatch_outcome_state: Literal[
        "not-started",
        "outcome-unknown",
        "terminal-success",
    ] = Field(alias="dispatchOutcomeState")
    redispatch_allowed: Literal[False] = Field(default=False, alias="redispatchAllowed")
    manual_review_required: bool = Field(alias="manualReviewRequired")
    event_digests: tuple[_Sha256, ...] = Field(alias="eventDigests", min_length=1, max_length=3)

    @field_validator("redispatch_allowed", "manual_review_required", mode="before")
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Supervisor journal flags must be JSON booleans")
        return value

    @field_validator("dispatch_started_at", "terminal_at")
    @classmethod
    def require_utc_optional_timestamp(cls, value: datetime | None) -> datetime | None:
        return _aware_utc(value, "journal timestamp") if value is not None else None

    @model_validator(mode="after")
    def bind_state(self) -> Self:
        expected = {
            SupervisorInvocationJournalState.INTENT_RECORDED: (
                None,
                None,
                None,
                None,
                None,
                "not-started",
                False,
                1,
            ),
            SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN: (
                "present",
                None,
                None,
                None,
                None,
                "outcome-unknown",
                True,
                2,
            ),
            SupervisorInvocationJournalState.TERMINAL_SUCCESS: (
                "present",
                "present",
                "present",
                self.intent.receipt_path,
                "present",
                "terminal-success",
                False,
                3,
            ),
        }[self.state]
        observed = (
            "present" if self.dispatch_started_at is not None else None,
            "present" if self.terminal_at is not None else None,
            "present" if self.final_root_digest is not None else None,
            self.receipt_path,
            "present" if self.receipt_sha256 is not None else None,
            self.dispatch_outcome_state,
            self.manual_review_required,
            len(self.event_digests),
        )
        if observed != expected or len(set(self.event_digests)) != len(self.event_digests):
            raise ValueError("Supervisor invocation journal state differs")
        if self.terminal_at is not None and (
            self.dispatch_started_at is None or self.terminal_at < self.dispatch_started_at
        ):
            raise ValueError("Supervisor invocation terminal state predates dispatch")
        digest = _state_digest(
            intent_digest=self.intent.intent_digest,
            state=self.state,
            dispatch_started_at=_format_optional_timestamp(self.dispatch_started_at),
            terminal_at=_format_optional_timestamp(self.terminal_at),
            final_root_digest=self.final_root_digest,
            receipt_path=self.receipt_path,
            receipt_sha256=self.receipt_sha256,
        )
        if self.state_digest and self.state_digest != digest:
            raise ValueError("Supervisor invocation journal State Digest differs")
        object.__setattr__(self, "state_digest", digest)
        return self

    @property
    def last_event_digest(self) -> str:
        """Return the verified hash-chain head."""

        return self.event_digests[-1]

    @property
    def dispatch_event_digest(self) -> str | None:
        """Return the single dispatch-started event digest, when present."""

        return self.event_digests[1] if len(self.event_digests) >= 2 else None


_METADATA_TABLE_SQL = """
    CREATE TABLE supervisor_invocation_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) STRICT
    """
_INTENTS_TABLE_SQL = """
    CREATE TABLE supervisor_invocation_intents (
        intent_id TEXT PRIMARY KEY NOT NULL,
        intent_digest TEXT NOT NULL,
        checkpoint_key TEXT NOT NULL UNIQUE,
        request_id TEXT NOT NULL UNIQUE,
        schedule_digest TEXT NOT NULL,
        request_binding_digest TEXT NOT NULL,
        dedicated_budget_policy_digest TEXT NOT NULL,
        planned_run_id TEXT NOT NULL UNIQUE,
        canonical_intent BLOB NOT NULL,
        state TEXT NOT NULL CHECK (state IN (
            'intent-recorded',
            'dispatch-started-outcome-unknown',
            'terminal-success'
        )),
        dispatch_started_at TEXT,
        terminal_at TEXT,
        final_root_digest TEXT,
        receipt_path TEXT,
        receipt_sha256 TEXT,
        state_digest TEXT NOT NULL,
        CHECK (
            (state = 'intent-recorded'
             AND dispatch_started_at IS NULL AND terminal_at IS NULL
             AND final_root_digest IS NULL AND receipt_path IS NULL
             AND receipt_sha256 IS NULL)
            OR
            (state = 'dispatch-started-outcome-unknown'
             AND dispatch_started_at IS NOT NULL AND terminal_at IS NULL
             AND final_root_digest IS NULL AND receipt_path IS NULL
             AND receipt_sha256 IS NULL)
            OR
            (state = 'terminal-success'
             AND dispatch_started_at IS NOT NULL AND terminal_at IS NOT NULL
             AND final_root_digest IS NOT NULL AND receipt_path IS NOT NULL
             AND receipt_sha256 IS NOT NULL)
        )
    ) STRICT
    """
_EVENTS_TABLE_SQL = """
    CREATE TABLE supervisor_invocation_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        intent_id TEXT NOT NULL REFERENCES supervisor_invocation_intents(intent_id),
        ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 3),
        from_state TEXT CHECK (from_state IN (
            'intent-recorded',
            'dispatch-started-outcome-unknown'
        )),
        to_state TEXT NOT NULL CHECK (to_state IN (
            'intent-recorded',
            'dispatch-started-outcome-unknown',
            'terminal-success'
        )),
        occurred_at TEXT NOT NULL,
        final_root_digest TEXT,
        receipt_path TEXT,
        receipt_sha256 TEXT,
        previous_event_digest TEXT,
        event_digest TEXT NOT NULL,
        UNIQUE(intent_id, ordinal)
    ) STRICT
    """
_EVENTS_INDEX_SQL = (
    "CREATE INDEX supervisor_invocation_events_intent_idx "
    "ON supervisor_invocation_events(intent_id, ordinal)"
)
_METADATA_NO_UPDATE_SQL = """
    CREATE TRIGGER supervisor_invocation_metadata_no_update
    BEFORE UPDATE ON supervisor_invocation_metadata
    BEGIN
        SELECT RAISE(ABORT, 'Supervisor invocation metadata is immutable');
    END
    """
_METADATA_NO_DELETE_SQL = """
    CREATE TRIGGER supervisor_invocation_metadata_no_delete
    BEFORE DELETE ON supervisor_invocation_metadata
    BEGIN
        SELECT RAISE(ABORT, 'Supervisor invocation metadata is immutable');
    END
    """
_METADATA_NO_REPLACE_SQL = """
    CREATE TRIGGER supervisor_invocation_metadata_no_replace
    BEFORE INSERT ON supervisor_invocation_metadata
    WHEN EXISTS (
        SELECT 1 FROM supervisor_invocation_metadata WHERE key = NEW.key
    )
    BEGIN
        SELECT RAISE(ABORT, 'Supervisor invocation metadata cannot be replaced');
    END
    """
_INTENTS_IMMUTABLE_SQL = """
    CREATE TRIGGER supervisor_invocation_intents_immutable
    BEFORE UPDATE OF
        intent_id, intent_digest, checkpoint_key, request_id, schedule_digest,
        request_binding_digest, dedicated_budget_policy_digest, planned_run_id,
        canonical_intent
    ON supervisor_invocation_intents
    BEGIN
        SELECT RAISE(ABORT, 'Supervisor invocation intent is immutable');
    END
    """
_INTENTS_ROWID_IMMUTABLE_SQL = """
    CREATE TRIGGER supervisor_invocation_intents_rowid_immutable
    BEFORE UPDATE ON supervisor_invocation_intents
    WHEN OLD.rowid != NEW.rowid
    BEGIN
        SELECT RAISE(ABORT, 'Supervisor invocation intent rowid is immutable');
    END
    """
_INTENTS_NO_DELETE_SQL = """
    CREATE TRIGGER supervisor_invocation_intents_no_delete
    BEFORE DELETE ON supervisor_invocation_intents
    BEGIN
        SELECT RAISE(ABORT, 'Supervisor invocation intents are append-only');
    END
    """
_INTENTS_NO_REPLACE_SQL = """
    CREATE TRIGGER supervisor_invocation_intents_no_replace
    BEFORE INSERT ON supervisor_invocation_intents
    WHEN EXISTS (
        SELECT 1 FROM supervisor_invocation_intents
        WHERE rowid = NEW.rowid OR intent_id = NEW.intent_id
           OR checkpoint_key = NEW.checkpoint_key OR request_id = NEW.request_id
           OR planned_run_id = NEW.planned_run_id
    )
    BEGIN
        SELECT RAISE(ABORT, 'Supervisor invocation intents cannot be replaced');
    END
    """
_INTENTS_STATE_TRANSITION_SQL = """
    CREATE TRIGGER supervisor_invocation_intents_state_transition
    BEFORE UPDATE OF state ON supervisor_invocation_intents
    WHEN NOT (
        (OLD.state = 'intent-recorded'
         AND NEW.state = 'dispatch-started-outcome-unknown')
        OR
        (OLD.state = 'dispatch-started-outcome-unknown'
         AND NEW.state = 'terminal-success')
    )
    BEGIN
        SELECT RAISE(ABORT, 'invalid Supervisor invocation state transition');
    END
    """
_EVENTS_NO_UPDATE_SQL = """
    CREATE TRIGGER supervisor_invocation_events_no_update
    BEFORE UPDATE ON supervisor_invocation_events
    BEGIN
        SELECT RAISE(ABORT, 'Supervisor invocation events are append-only');
    END
    """
_EVENTS_NO_DELETE_SQL = """
    CREATE TRIGGER supervisor_invocation_events_no_delete
    BEFORE DELETE ON supervisor_invocation_events
    BEGIN
        SELECT RAISE(ABORT, 'Supervisor invocation events are append-only');
    END
    """
_EVENTS_NO_REPLACE_SQL = """
    CREATE TRIGGER supervisor_invocation_events_no_replace
    BEFORE INSERT ON supervisor_invocation_events
    WHEN EXISTS (
        SELECT 1 FROM supervisor_invocation_events
        WHERE event_id = NEW.event_id
           OR (intent_id = NEW.intent_id AND ordinal = NEW.ordinal)
    )
    BEGIN
        SELECT RAISE(ABORT, 'Supervisor invocation events cannot be replaced');
    END
    """

_SCHEMA_OBJECT_SQL = {
    ("table", "supervisor_invocation_metadata"): _METADATA_TABLE_SQL,
    ("table", "supervisor_invocation_intents"): _INTENTS_TABLE_SQL,
    ("table", "supervisor_invocation_events"): _EVENTS_TABLE_SQL,
    ("index", "supervisor_invocation_events_intent_idx"): _EVENTS_INDEX_SQL,
    ("trigger", "supervisor_invocation_metadata_no_update"): _METADATA_NO_UPDATE_SQL,
    ("trigger", "supervisor_invocation_metadata_no_delete"): _METADATA_NO_DELETE_SQL,
    ("trigger", "supervisor_invocation_metadata_no_replace"): _METADATA_NO_REPLACE_SQL,
    ("trigger", "supervisor_invocation_intents_immutable"): _INTENTS_IMMUTABLE_SQL,
    (
        "trigger",
        "supervisor_invocation_intents_rowid_immutable",
    ): _INTENTS_ROWID_IMMUTABLE_SQL,
    ("trigger", "supervisor_invocation_intents_no_delete"): _INTENTS_NO_DELETE_SQL,
    ("trigger", "supervisor_invocation_intents_no_replace"): _INTENTS_NO_REPLACE_SQL,
    (
        "trigger",
        "supervisor_invocation_intents_state_transition",
    ): _INTENTS_STATE_TRANSITION_SQL,
    ("trigger", "supervisor_invocation_events_no_update"): _EVENTS_NO_UPDATE_SQL,
    ("trigger", "supervisor_invocation_events_no_delete"): _EVENTS_NO_DELETE_SQL,
    ("trigger", "supervisor_invocation_events_no_replace"): _EVENTS_NO_REPLACE_SQL,
}
_TABLES = frozenset(
    {
        "supervisor_invocation_metadata",
        "supervisor_invocation_intents",
        "supervisor_invocation_events",
    }
)


def _normalize_schema_sql(value: str) -> str:
    return " ".join(value.split())


_SCHEMA_DIGEST = sha256(
    canonical_json_bytes(
        {
            f"{kind}:{name}": _normalize_schema_sql(statement)
            for (kind, name), statement in sorted(_SCHEMA_OBJECT_SQL.items())
        },
        label="Supervisor invocation journal schema",
    )
).hexdigest()


class SupervisorInvocationJournal:
    """Crash-safe, one-host journal for durable Supervisor dispatch claiming."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], datetime] | None = None,
        run_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.path = Path(os.path.abspath(path))
        self._clock = clock or (lambda: datetime.now(UTC))
        self._run_id_factory = run_id_factory or RunStore.new_run_id
        _initialize(self.path)

    def claim(
        self,
        publication: SupervisorCheckpointSchedulePublication,
    ) -> SupervisorInvocationJournalEntry:
        """Record one exact checkpoint intent or return its exact durable retry."""

        try:
            schedule, binding = _publication_binding(publication)
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                existing = connection.execute(
                    "SELECT * FROM supervisor_invocation_intents WHERE checkpoint_key = ?",
                    (schedule.checkpoint_key,),
                ).fetchone()
                if existing is not None:
                    entry = _entry_from_row(connection, cast(sqlite3.Row, existing))
                    _require_exact_publication(entry.intent, schedule, binding)
                    return entry

                recorded_at = self._now()
                planned_run_id = self._run_id_factory()
                if not isinstance(planned_run_id, str):
                    raise ValueError("planned Supervisor Run ID must be a string")
                request_id = _stable_request_id(schedule, binding)
                intent = SupervisorInvocationIntent(
                    requestId=request_id,
                    campaignDigest=schedule.campaign_digest,
                    checkpointKey=schedule.checkpoint_key,
                    scheduleId=schedule.schedule_id,
                    scheduleDigest=schedule.schedule_digest,
                    scheduleRunId=binding.schedule_run_id,
                    scheduleRootDigest=binding.schedule_root_digest,
                    scheduleArtifactSha256=binding.schedule_artifact_sha256,
                    plannedCallIndex=schedule.planned_call_index,
                    requestBindingId=schedule.request_binding.request_binding_id,
                    requestBindingDigest=schedule.request_binding_digest,
                    dedicatedBudgetPolicyId=schedule.dedicated_budget_policy.policy_id,
                    dedicatedBudgetPolicyDigest=schedule.dedicated_budget_policy_digest,
                    plannedRunId=planned_run_id,
                    recordedAt=recorded_at,
                )
                state_digest = _state_digest(
                    intent_digest=intent.intent_digest,
                    state=SupervisorInvocationJournalState.INTENT_RECORDED,
                    dispatch_started_at=None,
                    terminal_at=None,
                    final_root_digest=None,
                    receipt_path=None,
                    receipt_sha256=None,
                )
                event_digest = _event_digest(
                    intent_id=intent.intent_id,
                    ordinal=1,
                    from_state=None,
                    to_state=SupervisorInvocationJournalState.INTENT_RECORDED,
                    occurred_at=_format_timestamp(recorded_at),
                    final_root_digest=None,
                    receipt_path=None,
                    receipt_sha256=None,
                    previous_event_digest=None,
                )
                connection.execute(
                    """
                    INSERT INTO supervisor_invocation_intents (
                        intent_id, intent_digest, checkpoint_key, request_id,
                        schedule_digest, request_binding_digest,
                        dedicated_budget_policy_digest, planned_run_id,
                        canonical_intent, state, dispatch_started_at, terminal_at,
                        final_root_digest, receipt_path, receipt_sha256, state_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?)
                    """,
                    (
                        intent.intent_id,
                        intent.intent_digest,
                        intent.checkpoint_key,
                        intent.request_id,
                        intent.schedule_digest,
                        intent.request_binding_digest,
                        intent.dedicated_budget_policy_digest,
                        intent.planned_run_id,
                        sqlite3.Binary(_intent_bytes(intent)),
                        SupervisorInvocationJournalState.INTENT_RECORDED.value,
                        state_digest,
                    ),
                )
                _insert_event(
                    connection,
                    intent_id=intent.intent_id,
                    ordinal=1,
                    from_state=None,
                    to_state=SupervisorInvocationJournalState.INTENT_RECORDED,
                    occurred_at=_format_timestamp(recorded_at),
                    final_root_digest=None,
                    receipt_path=None,
                    receipt_sha256=None,
                    previous_event_digest=None,
                    event_digest=event_digest,
                )
                row = _load_intent(connection, intent.intent_id)
                return _entry_from_row(connection, row)
        except SupervisorInvocationJournalError:
            raise
        except sqlite3.IntegrityError as exc:
            raise SupervisorInvocationJournalError(
                "Supervisor invocation claim conflicted with durable authority"
            ) from exc
        except (OSError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
            raise SupervisorInvocationJournalError(
                "Supervisor invocation claim failed closed"
            ) from exc

    def begin_dispatch(
        self,
        entry: SupervisorInvocationJournalEntry,
    ) -> SupervisorInvocationJournalEntry:
        """Consume the single dispatch claim; a retry never receives dispatch authority."""

        try:
            expected = _canonical_entry(entry)
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                row = _load_intent(connection, expected.intent.intent_id)
                current = _entry_from_row(connection, row)
                if current.state is not SupervisorInvocationJournalState.INTENT_RECORDED:
                    raise SupervisorInvocationJournalError(
                        "Supervisor invocation dispatch was already started; redispatch denied"
                    )
                if current != expected:
                    raise SupervisorInvocationJournalError(
                        "Supervisor invocation dispatch claim differs from durable intent"
                    )
                started_at = self._now()
                started_wire = _format_timestamp(started_at)
                state_digest = _state_digest(
                    intent_digest=current.intent.intent_digest,
                    state=SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN,
                    dispatch_started_at=started_wire,
                    terminal_at=None,
                    final_root_digest=None,
                    receipt_path=None,
                    receipt_sha256=None,
                )
                cursor = connection.execute(
                    """
                    UPDATE supervisor_invocation_intents
                    SET state = ?, dispatch_started_at = ?, state_digest = ?
                    WHERE intent_id = ? AND state = ? AND state_digest = ?
                    """,
                    (
                        SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value,
                        started_wire,
                        state_digest,
                        current.intent.intent_id,
                        SupervisorInvocationJournalState.INTENT_RECORDED.value,
                        current.state_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SupervisorInvocationJournalError(
                        "Supervisor invocation dispatch claim lost its atomic race"
                    )
                previous = current.event_digests[-1]
                event_digest = _event_digest(
                    intent_id=current.intent.intent_id,
                    ordinal=2,
                    from_state=SupervisorInvocationJournalState.INTENT_RECORDED,
                    to_state=(SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN),
                    occurred_at=started_wire,
                    final_root_digest=None,
                    receipt_path=None,
                    receipt_sha256=None,
                    previous_event_digest=previous,
                )
                _insert_event(
                    connection,
                    intent_id=current.intent.intent_id,
                    ordinal=2,
                    from_state=SupervisorInvocationJournalState.INTENT_RECORDED,
                    to_state=(SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN),
                    occurred_at=started_wire,
                    final_root_digest=None,
                    receipt_path=None,
                    receipt_sha256=None,
                    previous_event_digest=previous,
                    event_digest=event_digest,
                )
                return _entry_from_row(
                    connection,
                    _load_intent(connection, current.intent.intent_id),
                )
        except SupervisorInvocationJournalError:
            raise
        except sqlite3.IntegrityError as exc:
            raise SupervisorInvocationJournalError(
                "Supervisor invocation dispatch claim conflicted"
            ) from exc
        except (OSError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
            raise SupervisorInvocationJournalError(
                "Supervisor invocation dispatch claim failed closed"
            ) from exc

    def finalize_success(
        self,
        entry: SupervisorInvocationJournalEntry,
        *,
        final_root_digest: str,
        receipt_path: str,
        receipt_sha256: str,
    ) -> SupervisorInvocationJournalEntry:
        """Bind the exact final sealed receipt, idempotently, without redispatch."""

        try:
            expected = _canonical_entry(entry)
            _validate_digest(final_root_digest, "final_root_digest")
            _validate_digest(receipt_sha256, "receipt_sha256")
            if (
                validate_run_artifact_path(receipt_path) != expected.intent.receipt_path
                or receipt_path != expected.intent.receipt_path
            ):
                raise ValueError("Supervisor invocation receipt path differs")
            with _write_transaction(self.path) as connection:
                _validate_schema(connection)
                row = _load_intent(connection, expected.intent.intent_id)
                current = _entry_from_row(connection, row)
                if current.intent != expected.intent:
                    raise SupervisorInvocationJournalError(
                        "Supervisor invocation finalization differs from durable intent"
                    )
                if current.state is SupervisorInvocationJournalState.TERMINAL_SUCCESS:
                    if (
                        current.final_root_digest == final_root_digest
                        and current.receipt_path == receipt_path
                        and current.receipt_sha256 == receipt_sha256
                    ):
                        return current
                    raise SupervisorInvocationJournalError(
                        "Supervisor invocation was finalized with different receipt anchors"
                    )
                if (
                    current.state
                    is not SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    or expected.state
                    is not SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    or current != expected
                ):
                    raise SupervisorInvocationJournalError(
                        "Only the exact dispatch-started invocation can be finalized"
                    )
                terminal_at = self._now()
                terminal_wire = _format_timestamp(terminal_at)
                state_digest = _state_digest(
                    intent_digest=current.intent.intent_digest,
                    state=SupervisorInvocationJournalState.TERMINAL_SUCCESS,
                    dispatch_started_at=_format_timestamp(
                        cast(datetime, current.dispatch_started_at)
                    ),
                    terminal_at=terminal_wire,
                    final_root_digest=final_root_digest,
                    receipt_path=receipt_path,
                    receipt_sha256=receipt_sha256,
                )
                cursor = connection.execute(
                    """
                    UPDATE supervisor_invocation_intents
                    SET state = ?, terminal_at = ?, final_root_digest = ?,
                        receipt_path = ?, receipt_sha256 = ?, state_digest = ?
                    WHERE intent_id = ? AND state = ? AND state_digest = ?
                    """,
                    (
                        SupervisorInvocationJournalState.TERMINAL_SUCCESS.value,
                        terminal_wire,
                        final_root_digest,
                        receipt_path,
                        receipt_sha256,
                        state_digest,
                        current.intent.intent_id,
                        SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value,
                        current.state_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SupervisorInvocationJournalError(
                        "Supervisor invocation finalization lost its atomic race"
                    )
                previous = current.event_digests[-1]
                event_digest = _event_digest(
                    intent_id=current.intent.intent_id,
                    ordinal=3,
                    from_state=(SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN),
                    to_state=SupervisorInvocationJournalState.TERMINAL_SUCCESS,
                    occurred_at=terminal_wire,
                    final_root_digest=final_root_digest,
                    receipt_path=receipt_path,
                    receipt_sha256=receipt_sha256,
                    previous_event_digest=previous,
                )
                _insert_event(
                    connection,
                    intent_id=current.intent.intent_id,
                    ordinal=3,
                    from_state=(SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN),
                    to_state=SupervisorInvocationJournalState.TERMINAL_SUCCESS,
                    occurred_at=terminal_wire,
                    final_root_digest=final_root_digest,
                    receipt_path=receipt_path,
                    receipt_sha256=receipt_sha256,
                    previous_event_digest=previous,
                    event_digest=event_digest,
                )
                return _entry_from_row(
                    connection,
                    _load_intent(connection, current.intent.intent_id),
                )
        except SupervisorInvocationJournalError:
            raise
        except sqlite3.IntegrityError as exc:
            raise SupervisorInvocationJournalError(
                "Supervisor invocation finalization conflicted"
            ) from exc
        except (OSError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
            raise SupervisorInvocationJournalError(
                "Supervisor invocation finalization failed closed"
            ) from exc

    def inspect(self, intent_id: str) -> SupervisorInvocationJournalEntry:
        """Load and fully verify one journal head through a read-only transaction."""

        if not isinstance(intent_id, str) or not intent_id:
            raise SupervisorInvocationJournalError("Supervisor invocation intent ID is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                _validate_schema(connection)
                return _entry_from_row(connection, _load_intent(connection, intent_id))
        except SupervisorInvocationJournalError:
            raise
        except (
            OSError,
            RuntimeError,
            TypeError,
            ValidationError,
            ValueError,
            sqlite3.Error,
        ) as exc:
            raise SupervisorInvocationJournalError(
                "Supervisor invocation journal inspection failed closed"
            ) from exc

    def _now(self) -> datetime:
        return _aware_utc(self._clock(), "journal clock")


class _PublicationBinding(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schedule_run_id: str = Field(pattern=_RUN_ID_PATTERN)
    schedule_root_digest: _Sha256
    schedule_artifact_path: Literal["supervision/supervisor-checkpoint-schedule.json"]
    schedule_artifact_sha256: _Sha256


def _publication_binding(
    publication: SupervisorCheckpointSchedulePublication,
) -> tuple[SupervisorCheckpointSchedule, _PublicationBinding]:
    if not isinstance(publication, SupervisorCheckpointSchedulePublication):
        raise TypeError("Supervisor invocation claim requires a schedule publication")
    schedule = SupervisorCheckpointSchedule.model_validate(
        publication.schedule.model_dump(mode="json", by_alias=True)
    )
    if not isinstance(publication.run_path, Path):
        raise TypeError("Supervisor schedule publication path is invalid")
    binding = _PublicationBinding(
        schedule_run_id=publication.run_id,
        schedule_root_digest=publication.root_digest,
        schedule_artifact_path=cast(
            Literal["supervision/supervisor-checkpoint-schedule.json"],
            publication.artifact_path,
        ),
        schedule_artifact_sha256=publication.artifact_sha256,
    )
    if validate_run_artifact_path(binding.schedule_artifact_path) != _SCHEDULE_ARTIFACT_PATH:
        raise ValueError("Supervisor schedule publication artifact path differs")
    return schedule, binding


def _stable_request_id(
    schedule: SupervisorCheckpointSchedule,
    publication: _PublicationBinding,
) -> str:
    digest = _digest(
        "pajin.supervision.stable-provider-request/v1",
        {
            "campaignDigest": schedule.campaign_digest,
            "checkpointKey": schedule.checkpoint_key,
            "scheduleId": schedule.schedule_id,
            "scheduleDigest": schedule.schedule_digest,
            "scheduleRunId": publication.schedule_run_id,
            "scheduleRootDigest": publication.schedule_root_digest,
            "scheduleArtifactPath": publication.schedule_artifact_path,
            "scheduleArtifactSha256": publication.schedule_artifact_sha256,
            "plannedCallIndex": schedule.planned_call_index,
            "requestBindingId": schedule.request_binding.request_binding_id,
            "requestBindingDigest": schedule.request_binding_digest,
            "dedicatedBudgetPolicyId": schedule.dedicated_budget_policy.policy_id,
            "dedicatedBudgetPolicyDigest": schedule.dedicated_budget_policy_digest,
        },
    )
    return f"supervisor_{digest}"


def _require_exact_publication(
    intent: SupervisorInvocationIntent,
    schedule: SupervisorCheckpointSchedule,
    publication: _PublicationBinding,
) -> None:
    if (
        intent.request_id != _stable_request_id(schedule, publication)
        or intent.campaign_digest != schedule.campaign_digest
        or intent.checkpoint_key != schedule.checkpoint_key
        or intent.schedule_id != schedule.schedule_id
        or intent.schedule_digest != schedule.schedule_digest
        or intent.schedule_run_id != publication.schedule_run_id
        or intent.schedule_root_digest != publication.schedule_root_digest
        or intent.schedule_artifact_path != publication.schedule_artifact_path
        or intent.schedule_artifact_sha256 != publication.schedule_artifact_sha256
        or intent.planned_call_index != schedule.planned_call_index
        or intent.request_binding_id != schedule.request_binding.request_binding_id
        or intent.request_binding_digest != schedule.request_binding_digest
        or intent.dedicated_budget_policy_id != schedule.dedicated_budget_policy.policy_id
        or intent.dedicated_budget_policy_digest != schedule.dedicated_budget_policy_digest
    ):
        raise SupervisorInvocationJournalError(
            "Supervisor invocation checkpoint equivocation was rejected"
        )


def _canonical_entry(entry: SupervisorInvocationJournalEntry) -> SupervisorInvocationJournalEntry:
    if not isinstance(entry, SupervisorInvocationJournalEntry):
        raise TypeError("Supervisor invocation journal entry is invalid")
    return SupervisorInvocationJournalEntry.model_validate(
        entry.model_dump(mode="json", by_alias=True)
    )


def _intent_bytes(intent: SupervisorInvocationIntent) -> bytes:
    return canonical_json_bytes(
        intent.model_dump(mode="json", by_alias=True),
        label="Supervisor invocation intent",
        max_bytes=_MAX_INTENT_BYTES,
    )


def _entry_from_row(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
) -> SupervisorInvocationJournalEntry:
    raw = _required_bytes(row, "canonical_intent")
    intent = SupervisorInvocationIntent.model_validate_json(raw)
    if _intent_bytes(intent) != raw:
        raise SupervisorInvocationJournalError(
            "Supervisor invocation intent bytes are not canonical"
        )
    if (
        _required_text(row, "intent_id") != intent.intent_id
        or _required_digest(row, "intent_digest") != intent.intent_digest
        or _required_digest(row, "checkpoint_key") != intent.checkpoint_key
        or _required_text(row, "request_id") != intent.request_id
        or _required_digest(row, "schedule_digest") != intent.schedule_digest
        or _required_digest(row, "request_binding_digest") != intent.request_binding_digest
        or _required_digest(row, "dedicated_budget_policy_digest")
        != intent.dedicated_budget_policy_digest
        or _required_text(row, "planned_run_id") != intent.planned_run_id
    ):
        raise SupervisorInvocationJournalError(
            "Supervisor invocation duplicated index columns differ"
        )
    try:
        state = SupervisorInvocationJournalState(_required_text(row, "state"))
    except ValueError as exc:
        raise SupervisorInvocationJournalError(
            "Supervisor invocation journal state is invalid"
        ) from exc
    dispatch_wire = _optional_text(row, "dispatch_started_at")
    terminal_wire = _optional_text(row, "terminal_at")
    final_root = _optional_text(row, "final_root_digest")
    receipt_path = _optional_text(row, "receipt_path")
    receipt_sha = _optional_text(row, "receipt_sha256")
    event_digests = _validate_event_chain(
        connection,
        intent=intent,
        state=state,
        dispatch_started_at=dispatch_wire,
        terminal_at=terminal_wire,
        final_root_digest=final_root,
        receipt_path=receipt_path,
        receipt_sha256=receipt_sha,
    )
    entry = SupervisorInvocationJournalEntry(
        intent=intent,
        state=state,
        stateDigest=_required_digest(row, "state_digest"),
        dispatchStartedAt=(
            _parse_timestamp(dispatch_wire, "dispatch_started_at")
            if dispatch_wire is not None
            else None
        ),
        terminalAt=(
            _parse_timestamp(terminal_wire, "terminal_at") if terminal_wire is not None else None
        ),
        finalRootDigest=final_root,
        receiptPath=receipt_path,
        receiptSha256=receipt_sha,
        dispatchOutcomeState=cast(
            Literal["not-started", "outcome-unknown", "terminal-success"],
            {
                SupervisorInvocationJournalState.INTENT_RECORDED: "not-started",
                SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN: (
                    "outcome-unknown"
                ),
                SupervisorInvocationJournalState.TERMINAL_SUCCESS: "terminal-success",
            }[state],
        ),
        manualReviewRequired=(
            state is SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        ),
        eventDigests=event_digests,
    )
    expected_state_digest = _state_digest(
        intent_digest=intent.intent_digest,
        state=state,
        dispatch_started_at=dispatch_wire,
        terminal_at=terminal_wire,
        final_root_digest=final_root,
        receipt_path=receipt_path,
        receipt_sha256=receipt_sha,
    )
    if entry.state_digest != expected_state_digest:
        raise SupervisorInvocationJournalError(
            "Supervisor invocation journal state integrity check failed"
        )
    return entry


def _validate_event_chain(
    connection: sqlite3.Connection,
    *,
    intent: SupervisorInvocationIntent,
    state: SupervisorInvocationJournalState,
    dispatch_started_at: str | None,
    terminal_at: str | None,
    final_root_digest: str | None,
    receipt_path: str | None,
    receipt_sha256: str | None,
) -> tuple[str, ...]:
    rows = connection.execute(
        """
        SELECT * FROM supervisor_invocation_events
        WHERE intent_id = ? ORDER BY ordinal
        """,
        (intent.intent_id,),
    ).fetchall()
    expected_states = {
        SupervisorInvocationJournalState.INTENT_RECORDED: (
            SupervisorInvocationJournalState.INTENT_RECORDED,
        ),
        SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN: (
            SupervisorInvocationJournalState.INTENT_RECORDED,
            SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN,
        ),
        SupervisorInvocationJournalState.TERMINAL_SUCCESS: (
            SupervisorInvocationJournalState.INTENT_RECORDED,
            SupervisorInvocationJournalState.DISPATCH_STARTED_OUTCOME_UNKNOWN,
            SupervisorInvocationJournalState.TERMINAL_SUCCESS,
        ),
    }[state]
    if len(rows) != len(expected_states):
        raise SupervisorInvocationJournalError("Supervisor invocation event chain length differs")
    previous: str | None = None
    digests: list[str] = []
    for ordinal, (event, to_state) in enumerate(
        zip(rows, expected_states, strict=True),
        start=1,
    ):
        if type(event["ordinal"]) is not int or event["ordinal"] != ordinal:
            raise SupervisorInvocationJournalError("Supervisor invocation event ordinal differs")
        from_state = None if ordinal == 1 else expected_states[ordinal - 2]
        if (
            _optional_text(event, "from_state")
            != (from_state.value if from_state is not None else None)
            or _required_text(event, "to_state") != to_state.value
            or _optional_text(event, "previous_event_digest") != previous
        ):
            raise SupervisorInvocationJournalError("Supervisor invocation event transition differs")
        occurred_at = _required_text(event, "occurred_at")
        _parse_timestamp(occurred_at, "event occurred_at")
        event_final_root = _optional_text(event, "final_root_digest")
        event_receipt_path = _optional_text(event, "receipt_path")
        event_receipt_sha = _optional_text(event, "receipt_sha256")
        if to_state is not SupervisorInvocationJournalState.TERMINAL_SUCCESS and any(
            value is not None for value in (event_final_root, event_receipt_path, event_receipt_sha)
        ):
            raise SupervisorInvocationJournalError(
                "Non-terminal Supervisor invocation event contains receipt anchors"
            )
        digest = _required_digest(event, "event_digest")
        expected_digest = _event_digest(
            intent_id=intent.intent_id,
            ordinal=ordinal,
            from_state=from_state,
            to_state=to_state,
            occurred_at=occurred_at,
            final_root_digest=event_final_root,
            receipt_path=event_receipt_path,
            receipt_sha256=event_receipt_sha,
            previous_event_digest=previous,
        )
        if digest != expected_digest:
            raise SupervisorInvocationJournalError(
                "Supervisor invocation event integrity check failed"
            )
        previous = digest
        digests.append(digest)
    if _required_text(rows[0], "occurred_at") != _format_timestamp(intent.recorded_at):
        raise SupervisorInvocationJournalError(
            "Supervisor invocation intent event timestamp differs"
        )
    if state is not SupervisorInvocationJournalState.INTENT_RECORDED and (
        _required_text(rows[1], "occurred_at") != dispatch_started_at
    ):
        raise SupervisorInvocationJournalError(
            "Supervisor invocation dispatch event timestamp differs"
        )
    if state is SupervisorInvocationJournalState.TERMINAL_SUCCESS:
        terminal = rows[2]
        if (
            _required_text(terminal, "occurred_at") != terminal_at
            or _required_digest(terminal, "final_root_digest") != final_root_digest
            or _required_text(terminal, "receipt_path") != receipt_path
            or _required_digest(terminal, "receipt_sha256") != receipt_sha256
        ):
            raise SupervisorInvocationJournalError(
                "Supervisor invocation terminal event anchors differ"
            )
    return tuple(digests)


def _insert_event(
    connection: sqlite3.Connection,
    *,
    intent_id: str,
    ordinal: int,
    from_state: SupervisorInvocationJournalState | None,
    to_state: SupervisorInvocationJournalState,
    occurred_at: str,
    final_root_digest: str | None,
    receipt_path: str | None,
    receipt_sha256: str | None,
    previous_event_digest: str | None,
    event_digest: str,
) -> None:
    connection.execute(
        """
        INSERT INTO supervisor_invocation_events (
            intent_id, ordinal, from_state, to_state, occurred_at,
            final_root_digest, receipt_path, receipt_sha256,
            previous_event_digest, event_digest
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            intent_id,
            ordinal,
            from_state.value if from_state is not None else None,
            to_state.value,
            occurred_at,
            final_root_digest,
            receipt_path,
            receipt_sha256,
            previous_event_digest,
            event_digest,
        ),
    )


def _load_intent(connection: sqlite3.Connection, intent_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM supervisor_invocation_intents WHERE intent_id = ?",
        (intent_id,),
    ).fetchone()
    if row is None:
        raise SupervisorInvocationJournalError("Supervisor invocation intent was not found")
    return cast(sqlite3.Row, row)


def _state_digest(
    *,
    intent_digest: str,
    state: SupervisorInvocationJournalState,
    dispatch_started_at: str | None,
    terminal_at: str | None,
    final_root_digest: str | None,
    receipt_path: str | None,
    receipt_sha256: str | None,
) -> str:
    return _digest(
        "pajin.supervision.invocation-journal-state/v1",
        {
            "intentDigest": intent_digest,
            "state": state.value,
            "dispatchStartedAt": dispatch_started_at,
            "terminalAt": terminal_at,
            "finalRootDigest": final_root_digest,
            "receiptPath": receipt_path,
            "receiptSha256": receipt_sha256,
        },
    )


def _event_digest(
    *,
    intent_id: str,
    ordinal: int,
    from_state: SupervisorInvocationJournalState | None,
    to_state: SupervisorInvocationJournalState,
    occurred_at: str,
    final_root_digest: str | None,
    receipt_path: str | None,
    receipt_sha256: str | None,
    previous_event_digest: str | None,
) -> str:
    return _digest(
        "pajin.supervision.invocation-journal-event/v1",
        {
            "intentId": intent_id,
            "ordinal": ordinal,
            "fromState": from_state.value if from_state is not None else None,
            "toState": to_state.value,
            "occurredAt": occurred_at,
            "finalRootDigest": final_root_digest,
            "receiptPath": receipt_path,
            "receiptSha256": receipt_sha256,
            "previousEventDigest": previous_event_digest,
        },
    )


def _digest(domain: str, value: object) -> str:
    return sha256(
        domain.encode("ascii", errors="strict")
        + b"\x00"
        + canonical_json_bytes(
            value,
            label="Supervisor invocation journal identity",
            max_bytes=_MAX_INTENT_BYTES,
        )
    ).hexdigest()


def _initialize(path: Path) -> None:
    _require_safe_path(path)
    _require_safe_sidecars(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        path.parent.chmod(0o700)
    _require_safe_path(path)
    existing_size = path.stat().st_size if path.exists() else 0
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            path,
            isolation_level=None,
            timeout=_BUSY_TIMEOUT_MS / 1_000,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("BEGIN IMMEDIATE")
        tables = _application_tables(connection)
        if not tables:
            if existing_size != 0:
                raise SupervisorInvocationJournalError(
                    "Existing Supervisor invocation journal has no trusted schema"
                )
            mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if mode is None or str(mode[0]).lower() != "delete":
                raise SupervisorInvocationJournalError(
                    "Supervisor invocation journal requires DELETE journal mode"
                )
            for statement in _SCHEMA_OBJECT_SQL.values():
                connection.execute(statement)
            connection.executemany(
                "INSERT INTO supervisor_invocation_metadata(key, value) VALUES (?, ?)",
                (
                    ("schema_version", str(_SCHEMA_VERSION)),
                    ("schema_digest", _SCHEMA_DIGEST),
                ),
            )
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
        _validate_schema(connection)
        connection.execute("COMMIT")
        if os.name == "posix":
            path.chmod(0o600)
    except BaseException:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        if connection is not None:
            connection.close()
    _require_safe_path(path)
    _require_safe_sidecars(path)


@contextmanager
def _write_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_path(path)
    _require_safe_sidecars(path)
    identity = _file_identity(path)
    connection = _open_connection(path, readonly=False)
    if _file_identity(path) != identity:
        connection.close()
        raise SupervisorInvocationJournalError(
            "Supervisor invocation journal changed while it was opened"
        )
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
        _require_safe_path(path)
        _require_safe_sidecars(path)


@contextmanager
def _readonly_connection(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_path(path)
    _require_safe_sidecars(path)
    identity = _file_identity(path)
    connection = _open_connection(path, readonly=True)
    if _file_identity(path) != identity:
        connection.close()
        raise SupervisorInvocationJournalError(
            "Supervisor invocation journal changed while it was opened"
        )
    try:
        connection.execute("BEGIN")
        yield connection
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
        _require_safe_path(path)
        _require_safe_sidecars(path)


def _open_connection(path: Path, *, readonly: bool) -> sqlite3.Connection:
    target: str | Path = f"{path.as_uri()}?mode=ro" if readonly else path
    connection = sqlite3.connect(
        target,
        uri=readonly,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    if readonly:
        connection.execute("PRAGMA query_only = ON")
    else:
        connection.execute("PRAGMA synchronous = FULL")
    return connection


def _validate_schema(connection: sqlite3.Connection) -> None:
    if _application_tables(connection) != _TABLES:
        raise SupervisorInvocationJournalError("Supervisor invocation journal table set differs")
    metadata_rows = connection.execute(
        "SELECT key, value FROM supervisor_invocation_metadata ORDER BY key"
    ).fetchall()
    metadata = {str(row["key"]): str(row["value"]) for row in metadata_rows}
    user_version = connection.execute("PRAGMA user_version").fetchone()
    application_id = connection.execute("PRAGMA application_id").fetchone()
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    trusted_schema = connection.execute("PRAGMA trusted_schema").fetchone()
    if (
        metadata
        != {
            "schema_digest": _SCHEMA_DIGEST,
            "schema_version": str(_SCHEMA_VERSION),
        }
        or user_version is None
        or user_version[0] != _SCHEMA_VERSION
        or application_id is None
        or application_id[0] != _APPLICATION_ID
        or journal_mode is None
        or str(journal_mode[0]).lower() != "delete"
        or foreign_keys is None
        or foreign_keys[0] != 1
        or trusted_schema is None
        or trusted_schema[0] != 0
    ):
        raise SupervisorInvocationJournalError(
            "Supervisor invocation journal connection or version differs"
        )
    placeholders = ", ".join("?" for _ in _TABLES)
    rows = connection.execute(
        f"""
        SELECT type, name, sql FROM sqlite_master
        WHERE sql IS NOT NULL
          AND type IN ('table', 'index', 'trigger')
          AND (name IN ({placeholders}) OR tbl_name IN ({placeholders}))
        """,
        (*sorted(_TABLES), *sorted(_TABLES)),
    ).fetchall()
    actual = {
        (str(row["type"]), str(row["name"])): _normalize_schema_sql(str(row["sql"])) for row in rows
    }
    expected = {
        key: _normalize_schema_sql(statement) for key, statement in _SCHEMA_OBJECT_SQL.items()
    }
    if actual != expected:
        raise SupervisorInvocationJournalError(
            "Supervisor invocation journal schema fingerprint differs"
        )
    foreign_key_rows = connection.execute(
        "PRAGMA foreign_key_list(supervisor_invocation_events)"
    ).fetchall()
    signatures = {
        (
            str(row["table"]),
            str(row["from"]),
            str(row["to"]),
            str(row["on_update"]),
            str(row["on_delete"]),
        )
        for row in foreign_key_rows
    }
    if signatures != {
        (
            "supervisor_invocation_intents",
            "intent_id",
            "intent_id",
            "NO ACTION",
            "NO ACTION",
        )
    }:
        raise SupervisorInvocationJournalError("Supervisor invocation journal foreign key differs")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise SupervisorInvocationJournalError(
            "Supervisor invocation journal contains orphaned events"
        )
    quick_check = connection.execute("PRAGMA quick_check").fetchall()
    if len(quick_check) != 1 or quick_check[0][0] != "ok":
        raise SupervisorInvocationJournalError(
            "Supervisor invocation journal integrity check failed"
        )


def _application_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row["name"])
        for row in connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
    }


def _require_safe_path(path: Path) -> None:
    parent = path.parent
    for ancestor in (parent, *parent.parents):
        if ancestor.exists() and (
            ancestor.is_symlink() or (hasattr(ancestor, "is_junction") and ancestor.is_junction())
        ):
            raise SupervisorInvocationJournalError(
                "Supervisor invocation journal ancestor is unsafe"
            )
    if parent.exists() and not parent.is_dir():
        raise SupervisorInvocationJournalError("Supervisor invocation journal parent is unsafe")
    if path.exists() or path.is_symlink():
        file_stat = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or path.is_symlink()
            or (hasattr(path, "is_junction") and path.is_junction())
            or file_stat.st_nlink != 1
        ):
            raise SupervisorInvocationJournalError(
                "Supervisor invocation journal is not a single-link regular file"
            )


def _require_safe_sidecars(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not (sidecar.exists() or sidecar.is_symlink()):
            continue
        file_stat = sidecar.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or sidecar.is_symlink()
            or (hasattr(sidecar, "is_junction") and sidecar.is_junction())
            or file_stat.st_nlink != 1
        ):
            raise SupervisorInvocationJournalError(
                "Supervisor invocation journal sidecar is unsafe"
            )


def _file_identity(path: Path) -> tuple[tuple[int, int], tuple[int, int]]:
    parent_stat = path.parent.stat()
    file_stat = path.stat()
    return (
        (int(parent_stat.st_dev), int(parent_stat.st_ino)),
        (int(file_stat.st_dev), int(file_stat.st_ino)),
    )


def _required_text(row: sqlite3.Row, field: str) -> str:
    value = row[field]
    if type(value) is not str or not value:
        raise SupervisorInvocationJournalError(f"Supervisor journal {field} is invalid")
    return value


def _optional_text(row: sqlite3.Row, field: str) -> str | None:
    value = row[field]
    if value is None:
        return None
    if type(value) is not str or not value:
        raise SupervisorInvocationJournalError(f"Supervisor journal {field} is invalid")
    return value


def _required_bytes(row: sqlite3.Row, field: str) -> bytes:
    value = row[field]
    if type(value) is not bytes or not value:
        raise SupervisorInvocationJournalError(f"Supervisor journal {field} is invalid")
    return value


def _required_digest(row: sqlite3.Row, field: str) -> str:
    value = _required_text(row, field)
    _validate_digest(value, field)
    return value


def _validate_digest(value: str, field: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _aware_utc(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must include an explicit UTC offset or Z")
    return value.astimezone(UTC)


def _parse_timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} is not an ISO-8601 timestamp") from exc
    return _aware_utc(parsed, field)


def _format_timestamp(value: datetime) -> str:
    return _aware_utc(value, "timestamp").isoformat()


def _format_optional_timestamp(value: datetime | None) -> str | None:
    return _format_timestamp(value) if value is not None else None


__all__ = [
    "SUPERVISOR_INVOCATION_INTENT_API_VERSION",
    "SUPERVISOR_INVOCATION_JOURNAL_ENTRY_API_VERSION",
    "SupervisorInvocationIntent",
    "SupervisorInvocationJournal",
    "SupervisorInvocationJournalEntry",
    "SupervisorInvocationJournalError",
    "SupervisorInvocationJournalState",
]
