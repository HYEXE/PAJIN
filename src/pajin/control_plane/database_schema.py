"""Declarative schema and frozen migration metadata for the durable Control Plane."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

LEGACY_SCHEMA_VERSION = 1
REPLAY_AUTHORITY_SCHEMA_VERSION = 2
ARTIFACT_AUTHORITY_SCHEMA_VERSION = 3
REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION = 4
DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION = 5
REPLAY_TOOL_PERMIT_SCHEMA_VERSION = 6
REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION = 7
COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION = 8
REPLAY_FINALIZATION_SCHEMA_VERSION = 9
SUBMISSION_AND_LEASE_AUTHORITY_SCHEMA_VERSION = 10
REPLAY_PROJECTION_AUTHORITY_SCHEMA_VERSION = 11
REPLAY_RETEST_SOURCE_AUTHORITY_SCHEMA_VERSION = 12
CURRENT_SCHEMA_VERSION = REPLAY_RETEST_SOURCE_AUTHORITY_SCHEMA_VERSION
MAX_JOB_LEASE_LIFETIME_SECONDS = 24 * 60 * 60
_MIGRATION_BACKFILL_BATCH_SIZE = 500
_JSON_AUTHORITY_BATCH_SIZE = 8
_RUN_JSON_STORAGE_MAX_BYTES = 4 * 1024 * 1024
_JOB_JSON_STORAGE_MAX_BYTES = 8 * 1024 * 1024
_SQLITE_BUSY_TIMEOUT_MILLISECONDS = 30_000

LEGACY_CONTROL_PLANE_TABLES = frozenset(
    {"cp_runs", "cp_jobs", "cp_checkpoints", "cp_approvals", "cp_events"}
)
REPLAY_AUTHORITY_TABLES = frozenset(
    {
        "cp_replay_batches",
        "cp_replay_items",
        "cp_replay_tickets",
        "cp_replay_events",
    }
)
V2_CONTROL_PLANE_TABLES = frozenset(
    {*LEGACY_CONTROL_PLANE_TABLES, "cp_schema_version", *REPLAY_AUTHORITY_TABLES}
)
ARTIFACT_AUTHORITY_TABLES = frozenset({"cp_artifacts"})
V3_CONTROL_PLANE_TABLES = frozenset({*V2_CONTROL_PLANE_TABLES, *ARTIFACT_AUTHORITY_TABLES})
REPLAY_COMPILATION_AUTHORITY_TABLES = frozenset({"cp_replay_compilations"})
V4_CONTROL_PLANE_TABLES = frozenset(
    {*V3_CONTROL_PLANE_TABLES, *REPLAY_COMPILATION_AUTHORITY_TABLES}
)
REPLAY_RESERVATION_AUTHORITY_TABLES = frozenset(
    {
        "cp_replay_budget_accounts",
        "cp_replay_budget_reservations",
        "cp_replay_rate_accounts",
        "cp_replay_rate_reservations",
    }
)
V5_CONTROL_PLANE_TABLES = frozenset(
    {*V4_CONTROL_PLANE_TABLES, *REPLAY_RESERVATION_AUTHORITY_TABLES}
)
REPLAY_TOOL_PERMIT_AUTHORITY_TABLES = frozenset({"cp_replay_tool_permits"})
V6_CONTROL_PLANE_TABLES = frozenset(
    {*V5_CONTROL_PLANE_TABLES, *REPLAY_TOOL_PERMIT_AUTHORITY_TABLES}
)
REPLAY_EXECUTION_CONTEXT_AUTHORITY_TABLES = frozenset({"cp_replay_execution_contexts"})
V7_CONTROL_PLANE_TABLES = frozenset(
    {*V6_CONTROL_PLANE_TABLES, *REPLAY_EXECUTION_CONTEXT_AUTHORITY_TABLES}
)
V8_CONTROL_PLANE_TABLES = V7_CONTROL_PLANE_TABLES
REPLAY_FINALIZATION_AUTHORITY_TABLES = frozenset({"cp_replay_finalizations"})
V10_CONTROL_PLANE_TABLES = frozenset(
    {*V8_CONTROL_PLANE_TABLES, *REPLAY_FINALIZATION_AUTHORITY_TABLES}
)
REPLAY_PROJECTION_AUTHORITY_TABLES = frozenset({"cp_replay_projections"})
V11_CONTROL_PLANE_TABLES = frozenset(
    {*V10_CONTROL_PLANE_TABLES, *REPLAY_PROJECTION_AUTHORITY_TABLES}
)
REPLAY_RETEST_SOURCE_AUTHORITY_TABLES = frozenset({"cp_replay_retest_sources"})
CURRENT_CONTROL_PLANE_TABLES = frozenset(
    {*V11_CONTROL_PLANE_TABLES, *REPLAY_RETEST_SOURCE_AUTHORITY_TABLES}
)


def _lower_hex_check(value: str, length: int) -> str:
    """Return one portable CHECK expression for fixed-length lowercase hex."""

    stripped = value
    for character in "0123456789abcdef":
        stripped = f"replace({stripped}, '{character}', '')"
    return f"length({value}) = {length} AND length({stripped}) = 0"


_ASCII_ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _allowed_characters_check(value: str, allowed: str) -> str:
    """Return a portable CHECK that rejects every character outside ``allowed``."""

    stripped = value
    for character in allowed:
        stripped = f"replace({stripped}, '{character}', '')"
    return f"length({stripped}) = 0"


def _balanced_allowed_characters_check(value: str, allowed: str) -> str:
    """Equivalent character allowlist with logarithmic SQLite parser depth."""

    terms = [
        f"(length({value}) - length(replace({value}, '{character}', '')))" for character in allowed
    ]

    def balanced_sum(parts: list[str]) -> str:
        if len(parts) == 1:
            return parts[0]
        midpoint = len(parts) // 2
        return f"({balanced_sum(parts[:midpoint])} + {balanced_sum(parts[midpoint:])})"

    return f"length({value}) = {balanced_sum(terms)}"


class SchemaInitializationError(RuntimeError):
    """The durable Control Plane schema is unknown, partial, or corrupted."""


class Base(DeclarativeBase):
    pass


class RunRecord(Base):
    __tablename__ = "cp_runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    campaign_name: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    input: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    submission_key: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    current_checkpoint_id: Mapped[str | None] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    if TYPE_CHECKING:
        # Added after the exact schema-v9 metadata is frozen.
        submission_authority_digest: Mapped[str | None]


class JobRecord(Base):
    __tablename__ = "cp_jobs"
    __table_args__ = (
        Index("ix_cp_jobs_claim", "state", "available_at", "priority", "created_at"),
        Index("ux_cp_jobs_job_run", "job_id", "run_id", unique=True),
    )

    job_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("cp_runs.run_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(240), nullable=False, unique=True)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(String(200))
    lease_token_hash: Mapped[str | None] = mapped_column(String(64))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    if TYPE_CHECKING:
        # Added after the exact schema-v9 metadata is frozen.
        submission_authority_digest: Mapped[str | None]
        lease_deadline_at: Mapped[datetime | None]
        heartbeat_event_at: Mapped[datetime | None]


class CheckpointRecord(Base):
    __tablename__ = "cp_checkpoints"
    __table_args__ = (UniqueConstraint("run_id", "sequence", name="uq_checkpoint_run_sequence"),)

    checkpoint_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("cp_runs.run_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    key_id: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_by: Mapped[str | None] = mapped_column(String(200))
    continuation_job_id: Mapped[str | None] = mapped_column(
        ForeignKey("cp_jobs.job_id", ondelete="RESTRICT")
    )


class ApprovalRecord(Base):
    __tablename__ = "cp_approvals"
    __table_args__ = (
        UniqueConstraint("checkpoint_id", name="uq_approval_checkpoint"),
        Index("ix_cp_approval_state_expiry", "state", "expires_at"),
    )

    approval_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("cp_runs.run_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    checkpoint_id: Mapped[str] = mapped_column(
        ForeignKey("cp_checkpoints.checkpoint_id", ondelete="RESTRICT"), nullable=False
    )
    call_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_id: Mapped[str] = mapped_column(String(200), nullable=False)
    target: Mapped[str] = mapped_column(String(2_000), nullable=False)
    risk_tier: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(200), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_by: Mapped[str | None] = mapped_column(String(200))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_reason: Mapped[str | None] = mapped_column(Text)
    consumed_by: Mapped[str | None] = mapped_column(String(200))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EventRecord(Base):
    __tablename__ = "cp_events"
    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="uq_event_run_sequence"),
        Index("ix_cp_events_run_time", "run_id", "occurred_at"),
    )

    event_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("cp_runs.run_id", ondelete="RESTRICT"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(150), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SchemaVersionRecord(Base):
    """Applied forward-only Control Plane schema migration."""

    __tablename__ = "cp_schema_version"
    __table_args__ = (CheckConstraint("version > 0", name="ck_cp_schema_version_positive"),)

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    description: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ArtifactRecord(Base):
    """Immutable metadata for one repository-owned, verified Artifact version."""

    __tablename__ = "cp_artifacts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["producer_job_id", "producer_run_id"],
            ["cp_jobs.job_id", "cp_jobs.run_id"],
            name="fk_cp_artifacts_producer_job_run",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "length(artifact_id) = 41 AND "
            "substr(artifact_id, 1, 9) = 'artifact_' AND "
            + _lower_hex_check("substr(artifact_id, 10, 32)", 32),
            name="ck_cp_artifacts_artifact_id",
        ),
        CheckConstraint(
            "repository_version > 0 AND repository_version <= 2147483647",
            name="ck_cp_artifacts_repository_version",
        ),
        CheckConstraint(
            "length(producer_run_id) = 36 AND "
            "substr(producer_run_id, 1, 4) = 'run_' AND "
            + _lower_hex_check("substr(producer_run_id, 5, 32)", 32),
            name="ck_cp_artifacts_producer_run_id",
        ),
        CheckConstraint(
            "length(producer_job_id) = 36 AND "
            "substr(producer_job_id, 1, 4) = 'job_' AND "
            + _lower_hex_check("substr(producer_job_id, 5, 32)", 32),
            name="ck_cp_artifacts_producer_job_id",
        ),
        CheckConstraint(
            "producer_attempt > 0 AND producer_attempt <= 2147483647",
            name="ck_cp_artifacts_producer_attempt",
        ),
        CheckConstraint(
            "length(sealed_run_id) > 0 AND length(sealed_run_id) <= 64 AND "
            + _allowed_characters_check("substr(sealed_run_id, 1, 1)", _ASCII_ALPHANUMERIC)
            + " AND "
            + _allowed_characters_check("sealed_run_id", _ASCII_ALPHANUMERIC + "._:-"),
            name="ck_cp_artifacts_sealed_run_id",
        ),
        CheckConstraint(
            "length(media_type) >= 3 AND length(media_type) <= 200 AND "
            + _allowed_characters_check("substr(media_type, 1, 1)", _ASCII_ALPHANUMERIC)
            + " AND "
            + _allowed_characters_check("media_type", _ASCII_ALPHANUMERIC + ".+-/")
            + " AND length(media_type) = length(replace(media_type, '/', '')) + 1 "
            "AND substr(media_type, length(media_type), 1) <> '/' "
            "AND length(replace(media_type, '/.', '')) = length(media_type) "
            "AND length(replace(media_type, '/+', '')) = length(media_type) "
            "AND length(replace(media_type, '/-', '')) = length(media_type)",
            name="ck_cp_artifacts_media_type",
        ),
        CheckConstraint(
            "length(schema_kind) > 0 AND length(schema_kind) <= 200 AND "
            + _allowed_characters_check("substr(schema_kind, 1, 1)", _ASCII_ALPHANUMERIC)
            + " AND "
            + _allowed_characters_check("schema_kind", _ASCII_ALPHANUMERIC + "._:-"),
            name="ck_cp_artifacts_schema_kind",
        ),
        CheckConstraint(
            "byte_length > 0 AND byte_length <= 2147483647",
            name="ck_cp_artifacts_byte_length",
        ),
        CheckConstraint(
            _lower_hex_check("content_digest", 64),
            name="ck_cp_artifacts_content_digest",
        ),
        CheckConstraint(
            _lower_hex_check("root_digest", 64),
            name="ck_cp_artifacts_root_digest",
        ),
        CheckConstraint(
            "length(created_by) > 0 AND length(created_by) <= 200",
            name="ck_cp_artifacts_created_by",
        ),
        CheckConstraint(
            "length(storage_key) > 0 AND length(storage_key) <= 500",
            name="ck_cp_artifacts_storage_key",
        ),
        CheckConstraint(
            "length(idempotency_key) >= 8 AND length(idempotency_key) <= 200",
            name="ck_cp_artifacts_idempotency_key",
        ),
        CheckConstraint(
            _lower_hex_check("admission_digest", 64),
            name="ck_cp_artifacts_admission_digest",
        ),
        UniqueConstraint("storage_key", name="uq_cp_artifacts_storage_key"),
        UniqueConstraint("idempotency_key", name="uq_cp_artifacts_idempotency_key"),
        UniqueConstraint(
            "artifact_id",
            "repository_version",
            "content_digest",
            "root_digest",
            "media_type",
            "schema_kind",
            "byte_length",
            "sealed_run_id",
            "producer_run_id",
            "created_by",
            name="uq_cp_artifacts_authority_binding",
        ),
        Index(
            "ix_cp_artifacts_producer_run",
            "producer_run_id",
            "producer_attempt",
        ),
        Index("ix_cp_artifacts_sealed_run", "sealed_run_id"),
    )

    artifact_id: Mapped[str] = mapped_column(String(41), primary_key=True)
    repository_version: Mapped[int] = mapped_column(Integer, primary_key=True)
    producer_run_id: Mapped[str] = mapped_column(
        ForeignKey("cp_runs.run_id", ondelete="RESTRICT"), nullable=False
    )
    producer_job_id: Mapped[str] = mapped_column(String(36), nullable=False)
    producer_attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    sealed_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    media_type: Mapped[str] = mapped_column(String(200), nullable=False)
    schema_kind: Mapped[str] = mapped_column(String(200), nullable=False)
    byte_length: Mapped[int] = mapped_column(Integer, nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    root_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    admission_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ReplayBatchRecord(Base):
    """Immutable source admission and aggregate Replay lifecycle authority."""

    __tablename__ = "cp_replay_batches"
    __table_args__ = (
        ForeignKeyConstraint(
            [
                "source_artifact_id",
                "source_repository_version",
                "source_content_digest",
                "source_root_digest",
                "source_media_type",
                "source_schema_kind",
                "source_byte_length",
                "source_artifact_run_id",
                "source_run_id",
                "source_created_by",
            ],
            [
                "cp_artifacts.artifact_id",
                "cp_artifacts.repository_version",
                "cp_artifacts.content_digest",
                "cp_artifacts.root_digest",
                "cp_artifacts.media_type",
                "cp_artifacts.schema_kind",
                "cp_artifacts.byte_length",
                "cp_artifacts.sealed_run_id",
                "cp_artifacts.producer_run_id",
                "cp_artifacts.created_by",
            ],
            name="fk_cp_replay_batches_source_artifact_authority",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "state IN ('planned', 'running', 'gating', 'completed', 'failed', 'cancelled')",
            name="ck_cp_replay_batches_state",
        ),
        CheckConstraint(
            "mode IN ('ai-redteam', 'bug-bounty', 'ctf')",
            name="ck_cp_replay_batches_mode",
        ),
        CheckConstraint(
            "purpose IN ('confirmation', 'remediation-retest')",
            name="ck_cp_replay_batches_purpose",
        ),
        CheckConstraint(
            "source_repository_version > 0",
            name="ck_cp_replay_batches_repository_version",
        ),
        CheckConstraint(
            "length(source_content_digest) = 64",
            name="ck_cp_replay_batches_content_digest",
        ),
        CheckConstraint(
            "length(source_root_digest) = 64",
            name="ck_cp_replay_batches_root_digest",
        ),
        CheckConstraint("source_byte_length > 0", name="ck_cp_replay_batches_source_byte_length"),
        CheckConstraint("cas_version > 0", name="ck_cp_replay_batches_cas_version"),
        CheckConstraint(
            "(cancelled_at IS NULL AND cancellation_reason IS NULL) OR "
            "(cancelled_at IS NOT NULL AND cancellation_reason IS NOT NULL)",
            name="ck_cp_replay_batches_cancellation_fields",
        ),
        CheckConstraint(
            "state <> 'cancelled' OR cancelled_at IS NOT NULL",
            name="ck_cp_replay_batches_cancelled_timestamp",
        ),
        UniqueConstraint("batch_id", "source_run_id", name="uq_cp_replay_batches_batch_source_run"),
        UniqueConstraint("batch_id", "source_root_digest", name="uq_cp_replay_batches_batch_root"),
        Index("ix_cp_replay_batches_run_state", "source_run_id", "state"),
    )

    batch_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    source_run_id: Mapped[str] = mapped_column(
        ForeignKey("cp_runs.run_id", ondelete="RESTRICT"), nullable=False
    )
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    campaign_name: Mapped[str] = mapped_column(String(128), nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    source_artifact_id: Mapped[str] = mapped_column(String(41), nullable=False)
    source_repository_version: Mapped[int] = mapped_column(Integer, nullable=False)
    source_content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_root_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_artifact_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_media_type: Mapped[str] = mapped_column(String(200), nullable=False)
    source_schema_kind: Mapped[str] = mapped_column(String(200), nullable=False)
    source_byte_length: Mapped[int] = mapped_column(Integer, nullable=False)
    source_created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    mode: Mapped[str] = mapped_column(String(80), nullable=False)
    purpose: Mapped[str] = mapped_column(String(80), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(100), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    cas_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    cancellation_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReplayItemRecord(Base):
    """One admitted Candidate and its server-owned Replay progress."""

    __tablename__ = "cp_replay_items"
    __table_args__ = (
        ForeignKeyConstraint(
            ["batch_id", "source_run_id"],
            ["cp_replay_batches.batch_id", "cp_replay_batches.source_run_id"],
            name="fk_cp_replay_items_batch_source_run",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "state IN ('pending', 'queued', 'running', 'verified', 'gated', "
            "'retry-pending', 'failed', 'cancelled')",
            name="ck_cp_replay_items_state",
        ),
        CheckConstraint("ordinal >= 0", name="ck_cp_replay_items_ordinal"),
        CheckConstraint(
            "length(candidate_digest) = 64",
            name="ck_cp_replay_items_candidate_digest",
        ),
        CheckConstraint(
            "length(contract_digest) = 64",
            name="ck_cp_replay_items_contract_digest",
        ),
        CheckConstraint(
            "length(compilation_digest) = 64",
            name="ck_cp_replay_items_compilation_digest",
        ),
        CheckConstraint("length(grant_digest) = 64", name="ck_cp_replay_items_grant_digest"),
        CheckConstraint("required_attempts > 0", name="ck_cp_replay_items_required_attempts"),
        CheckConstraint("max_attempts > 0", name="ck_cp_replay_items_max_attempts"),
        CheckConstraint(
            "required_attempts <= max_attempts",
            name="ck_cp_replay_items_required_within_max",
        ),
        CheckConstraint(
            "attempts >= 0 AND attempts <= max_attempts",
            name="ck_cp_replay_items_attempts",
        ),
        UniqueConstraint("item_id", "batch_id", name="uq_cp_replay_items_item_batch"),
        UniqueConstraint(
            "item_id",
            "batch_id",
            "grant_digest",
            "compilation_digest",
            name="uq_cp_replay_items_authority_binding",
        ),
        UniqueConstraint("batch_id", "ordinal", name="uq_cp_replay_items_batch_ordinal"),
        UniqueConstraint("replay_run_id", name="uq_cp_replay_items_replay_run"),
        UniqueConstraint("batch_id", "candidate_id", name="uq_cp_replay_items_batch_candidate"),
        UniqueConstraint(
            "batch_id",
            "compilation_digest",
            name="uq_cp_replay_items_batch_compilation",
        ),
        UniqueConstraint(
            "batch_id",
            "candidate_id",
            "contract_digest",
            "compilation_digest",
            "required_attempts",
            name="uq_cp_replay_items_authority",
        ),
        Index("ix_cp_replay_items_batch_state", "batch_id", "state"),
    )

    item_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(80), nullable=False)
    source_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    replay_run_id: Mapped[str] = mapped_column(
        ForeignKey("cp_runs.run_id", ondelete="RESTRICT"), nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    candidate_id: Mapped[str] = mapped_column(String(200), nullable=False)
    candidate_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    contract_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    compilation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    grant_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    required_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ReplayTicketRecord(Base):
    """Single-use execution authority burned atomically when its Job is claimed."""

    __tablename__ = "cp_replay_tickets"
    __table_args__ = (
        ForeignKeyConstraint(
            ["item_id", "batch_id", "grant_digest", "compilation_digest"],
            [
                "cp_replay_items.item_id",
                "cp_replay_items.batch_id",
                "cp_replay_items.grant_digest",
                "cp_replay_items.compilation_digest",
            ],
            name="fk_cp_replay_tickets_item_authority",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["batch_id", "source_root_digest"],
            ["cp_replay_batches.batch_id", "cp_replay_batches.source_root_digest"],
            name="fk_cp_replay_tickets_batch_root",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["job_id", "replay_run_id"],
            ["cp_jobs.job_id", "cp_jobs.run_id"],
            name="fk_cp_replay_tickets_job_run",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "state IN ('issued', 'claimed', 'finalized', 'abandoned')",
            name="ck_cp_replay_tickets_state",
        ),
        CheckConstraint("attempt_number > 0", name="ck_cp_replay_tickets_attempt"),
        CheckConstraint("fencing_value > 0", name="ck_cp_replay_tickets_fence"),
        CheckConstraint("length(grant_digest) = 64", name="ck_cp_replay_tickets_grant_digest"),
        CheckConstraint(
            "length(source_root_digest) = 64",
            name="ck_cp_replay_tickets_source_root_digest",
        ),
        CheckConstraint(
            "length(compilation_digest) = 64",
            name="ck_cp_replay_tickets_compilation_digest",
        ),
        CheckConstraint("expires_at > issued_at", name="ck_cp_replay_tickets_expiry"),
        CheckConstraint(
            "(claim_principal IS NULL AND executor_profile IS NULL "
            "AND lease_token_hash IS NULL AND lease_expires_at IS NULL AND claimed_at IS NULL) "
            "OR (claim_principal IS NOT NULL AND executor_profile IS NOT NULL "
            "AND lease_token_hash IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND claimed_at IS NOT NULL)",
            name="ck_cp_replay_tickets_claim_fields",
        ),
        CheckConstraint(
            "(state = 'issued' AND claimed_at IS NULL AND finalized_at IS NULL "
            "AND abandoned_at IS NULL AND abandon_reason IS NULL AND result_digest IS NULL) "
            "OR (state = 'claimed' AND claimed_at IS NOT NULL AND finalized_at IS NULL "
            "AND abandoned_at IS NULL AND abandon_reason IS NULL AND result_digest IS NULL) "
            "OR (state = 'finalized' AND claimed_at IS NOT NULL AND finalized_at IS NOT NULL "
            "AND abandoned_at IS NULL AND abandon_reason IS NULL "
            "AND result_digest IS NOT NULL) "
            "OR (state = 'abandoned' AND finalized_at IS NULL AND abandoned_at IS NOT NULL "
            "AND abandon_reason IS NOT NULL AND result_digest IS NULL)",
            name="ck_cp_replay_tickets_state_fields",
        ),
        CheckConstraint(
            "result_digest IS NULL OR length(result_digest) = 64",
            name="ck_cp_replay_tickets_result_digest",
        ),
        UniqueConstraint("job_id", name="uq_cp_replay_tickets_job"),
        UniqueConstraint("replay_run_id", name="uq_cp_replay_tickets_replay_run"),
        UniqueConstraint("item_id", "attempt_number", name="uq_cp_replay_tickets_item_attempt"),
        UniqueConstraint("item_id", "fencing_value", name="uq_cp_replay_tickets_item_fence"),
        UniqueConstraint(
            "ticket_id",
            "item_id",
            "batch_id",
            "job_id",
            "replay_run_id",
            name="uq_cp_replay_tickets_binding",
        ),
        Index("ix_cp_replay_tickets_item_state", "item_id", "state"),
        Index("ix_cp_replay_tickets_claim", "state", "expires_at", "issued_at"),
    )

    ticket_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(80), nullable=False)
    item_id: Mapped[str] = mapped_column(String(80), nullable=False)
    job_id: Mapped[str] = mapped_column(String(64), nullable=False)
    replay_run_id: Mapped[str] = mapped_column(
        ForeignKey("cp_runs.run_id", ondelete="RESTRICT"), nullable=False
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    fencing_value: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    grant_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_root_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    compilation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    executor_profile: Mapped[str | None] = mapped_column(String(200))
    claim_principal: Mapped[str | None] = mapped_column(String(200))
    lease_token_hash: Mapped[str | None] = mapped_column(String(64))
    result_digest: Mapped[str | None] = mapped_column(String(64))
    abandon_reason: Mapped[str | None] = mapped_column(Text)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    abandoned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    if TYPE_CHECKING:
        # Added to the runtime mapping after the exact schema-v4 metadata is frozen.
        compilation_id: Mapped[str]
        budget_reservation_id: Mapped[str]
        rate_reservation_id: Mapped[str]


class ReplayEventRecord(Base):
    """Append-only audit event for a Replay authority state transition."""

    __tablename__ = "cp_replay_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["item_id", "batch_id"],
            ["cp_replay_items.item_id", "cp_replay_items.batch_id"],
            name="fk_cp_replay_events_item_batch",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["ticket_id", "item_id", "batch_id", "job_id", "run_id"],
            [
                "cp_replay_tickets.ticket_id",
                "cp_replay_tickets.item_id",
                "cp_replay_tickets.batch_id",
                "cp_replay_tickets.job_id",
                "cp_replay_tickets.replay_run_id",
            ],
            name="fk_cp_replay_events_ticket_binding",
            ondelete="RESTRICT",
        ),
        CheckConstraint("sequence > 0", name="ck_cp_replay_events_sequence"),
        CheckConstraint(
            "ticket_id IS NULL OR (item_id IS NOT NULL AND job_id IS NOT NULL "
            "AND run_id IS NOT NULL)",
            name="ck_cp_replay_events_ticket_context",
        ),
        UniqueConstraint("batch_id", "sequence", name="uq_cp_replay_events_batch_sequence"),
        Index("ix_cp_replay_events_batch_time", "batch_id", "occurred_at"),
    )

    event_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    batch_id: Mapped[str] = mapped_column(
        ForeignKey("cp_replay_batches.batch_id", ondelete="RESTRICT"), nullable=False
    )
    item_id: Mapped[str | None] = mapped_column(String(80))
    ticket_id: Mapped[str | None] = mapped_column(String(80))
    job_id: Mapped[str | None] = mapped_column(ForeignKey("cp_jobs.job_id", ondelete="RESTRICT"))
    run_id: Mapped[str | None] = mapped_column(ForeignKey("cp_runs.run_id", ondelete="RESTRICT"))
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(150), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def _build_v2_metadata() -> MetaData:
    """Build the exact schema-v2 metadata used only for safe forward migration."""

    metadata = MetaData()
    copied = {*LEGACY_CONTROL_PLANE_TABLES, SchemaVersionRecord.__tablename__}
    for table in Base.metadata.sorted_tables:
        if table.name in copied:
            table.to_metadata(metadata)

    Table(
        "cp_replay_batches",
        metadata,
        Column("batch_id", String(80), primary_key=True),
        Column(
            "source_run_id",
            String(64),
            ForeignKey("cp_runs.run_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        Column("idempotency_key", String(200), nullable=False, unique=True),
        Column("campaign_name", String(128), nullable=False),
        Column("created_by", String(200), nullable=False),
        Column("source_artifact_id", String(200), nullable=False),
        Column("source_repository_version", Integer, nullable=False),
        Column("source_content_digest", String(64), nullable=False),
        Column("source_root_digest", String(64), nullable=False),
        Column("source_media_type", String(200), nullable=False),
        Column("source_schema_kind", String(200), nullable=False),
        Column("source_byte_length", Integer, nullable=False),
        Column("source_created_by", String(200), nullable=False),
        Column("mode", String(80), nullable=False),
        Column("purpose", String(80), nullable=False),
        Column("policy_version", String(100), nullable=False),
        Column("state", String(32), nullable=False),
        Column("cas_version", Integer, nullable=False),
        Column("cancellation_reason", Text),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
        Column("cancelled_at", DateTime(timezone=True)),
        CheckConstraint(
            "state IN ('planned', 'running', 'gating', 'completed', 'failed', 'cancelled')",
            name="ck_cp_replay_batches_state",
        ),
        CheckConstraint(
            "mode IN ('ai-redteam', 'bug-bounty', 'ctf')",
            name="ck_cp_replay_batches_mode",
        ),
        CheckConstraint(
            "purpose IN ('confirmation', 'remediation-retest')",
            name="ck_cp_replay_batches_purpose",
        ),
        CheckConstraint(
            "source_repository_version > 0",
            name="ck_cp_replay_batches_repository_version",
        ),
        CheckConstraint(
            "length(source_content_digest) = 64",
            name="ck_cp_replay_batches_content_digest",
        ),
        CheckConstraint(
            "length(source_root_digest) = 64",
            name="ck_cp_replay_batches_root_digest",
        ),
        CheckConstraint(
            "source_byte_length > 0",
            name="ck_cp_replay_batches_source_byte_length",
        ),
        CheckConstraint("cas_version > 0", name="ck_cp_replay_batches_cas_version"),
        CheckConstraint(
            "(cancelled_at IS NULL AND cancellation_reason IS NULL) OR "
            "(cancelled_at IS NOT NULL AND cancellation_reason IS NOT NULL)",
            name="ck_cp_replay_batches_cancellation_fields",
        ),
        CheckConstraint(
            "state <> 'cancelled' OR cancelled_at IS NOT NULL",
            name="ck_cp_replay_batches_cancelled_timestamp",
        ),
        UniqueConstraint("batch_id", "source_run_id", name="uq_cp_replay_batches_batch_source_run"),
        UniqueConstraint("batch_id", "source_root_digest", name="uq_cp_replay_batches_batch_root"),
        Index("ix_cp_replay_batches_run_state", "source_run_id", "state"),
    )
    for table in Base.metadata.sorted_tables:
        if table.name in REPLAY_AUTHORITY_TABLES - {"cp_replay_batches"}:
            table.to_metadata(metadata)
    return metadata


_V2_METADATA = _build_v2_metadata()


def _build_v3_metadata() -> MetaData:
    """Freeze the exact schema-v3 metadata before v4 authority is attached."""

    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name in V3_CONTROL_PLANE_TABLES:
            table.to_metadata(metadata)
    return metadata


_V3_METADATA = _build_v3_metadata()


cast(Table, ReplayItemRecord.__table__).append_constraint(
    UniqueConstraint(
        "item_id",
        "batch_id",
        "candidate_id",
        "candidate_digest",
        "contract_digest",
        name="uq_cp_replay_items_compilation_plan",
    )
)


class ReplayCompilationRecord(Base):
    """Canonical, append-only ReplayCompilation bytes bound to one Replay item."""

    __tablename__ = "cp_replay_compilations"
    __table_args__ = (
        ForeignKeyConstraint(
            [
                "item_id",
                "batch_id",
                "candidate_id",
                "candidate_digest",
                "contract_digest",
            ],
            [
                "cp_replay_items.item_id",
                "cp_replay_items.batch_id",
                "cp_replay_items.candidate_id",
                "cp_replay_items.candidate_digest",
                "cp_replay_items.contract_digest",
            ],
            name="fk_cp_replay_compilations_item_plan",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "length(compilation_id) = 51 AND "
            "substr(compilation_id, 1, 19) = 'replay-compilation_' AND "
            + _lower_hex_check("substr(compilation_id, 20, 32)", 32),
            name="ck_cp_replay_compilations_compilation_id",
        ),
        CheckConstraint(
            "length(item_id) > 0 AND length(item_id) <= 80",
            name="ck_cp_replay_compilations_item_id",
        ),
        CheckConstraint(
            "length(batch_id) > 0 AND length(batch_id) <= 80",
            name="ck_cp_replay_compilations_batch_id",
        ),
        CheckConstraint(
            "length(candidate_id) > 0 AND length(candidate_id) <= 200",
            name="ck_cp_replay_compilations_candidate_id",
        ),
        CheckConstraint(
            "length(replay_run_id) = 36 AND "
            "substr(replay_run_id, 1, 4) = 'run_' AND "
            + _lower_hex_check("substr(replay_run_id, 5, 32)", 32),
            name="ck_cp_replay_compilations_replay_run_id",
        ),
        CheckConstraint(
            _lower_hex_check("candidate_digest", 64),
            name="ck_cp_replay_compilations_candidate_digest",
        ),
        CheckConstraint(
            _lower_hex_check("contract_digest", 64),
            name="ck_cp_replay_compilations_contract_digest",
        ),
        CheckConstraint(
            _lower_hex_check("compilation_digest", 64),
            name="ck_cp_replay_compilations_compilation_digest",
        ),
        CheckConstraint(
            _lower_hex_check("grant_digest", 64),
            name="ck_cp_replay_compilations_grant_digest",
        ),
        CheckConstraint(
            "byte_length > 0 AND byte_length <= 2147483647 "
            "AND length(canonical_compilation) = byte_length",
            name="ck_cp_replay_compilations_canonical_bytes",
        ),
        UniqueConstraint(
            "compilation_digest",
            name="uq_cp_replay_compilations_compilation_digest",
        ),
        UniqueConstraint(
            "replay_run_id",
            name="uq_cp_replay_compilations_replay_run",
        ),
        Index("ix_cp_replay_compilations_batch", "batch_id", "created_at"),
        Index("ix_cp_replay_compilations_item", "item_id", "created_at"),
    )

    compilation_id: Mapped[str] = mapped_column(String(51), primary_key=True)
    item_id: Mapped[str] = mapped_column(String(80), nullable=False)
    batch_id: Mapped[str] = mapped_column(String(80), nullable=False)
    candidate_id: Mapped[str] = mapped_column(String(200), nullable=False)
    replay_run_id: Mapped[str] = mapped_column(
        ForeignKey("cp_runs.run_id", ondelete="RESTRICT"), nullable=False
    )
    candidate_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    contract_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    compilation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    grant_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_compilation: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    byte_length: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def _build_v4_metadata() -> MetaData:
    """Freeze the exact schema-v4 metadata before durable permits are attached."""

    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name in V4_CONTROL_PLANE_TABLES:
            table.to_metadata(metadata)
    return metadata


_V4_METADATA = _build_v4_metadata()


_replay_compilation_table = cast(Table, ReplayCompilationRecord.__table__)
_replay_compilation_table.append_constraint(
    UniqueConstraint(
        "compilation_id",
        "item_id",
        "batch_id",
        "replay_run_id",
        "compilation_digest",
        "grant_digest",
        name="uq_cp_replay_compilations_ticket_authority",
    )
)
_replay_compilation_table.append_constraint(
    UniqueConstraint(
        "compilation_id",
        "item_id",
        "batch_id",
        name="uq_cp_replay_compilations_reservation_authority",
    )
)

_replay_ticket_table = cast(Table, ReplayTicketRecord.__table__)
_legacy_ticket_item_authority = cast(
    ForeignKeyConstraint,
    next(
        constraint
        for constraint in _replay_ticket_table.constraints
        if constraint.name == "fk_cp_replay_tickets_item_authority"
    ),
)
_replay_ticket_table.constraints.remove(_legacy_ticket_item_authority)
for _foreign_key in _legacy_ticket_item_authority.elements:
    _foreign_key.parent.foreign_keys.discard(_foreign_key)
    _replay_ticket_table.foreign_keys.discard(_foreign_key)
ReplayTicketRecord.compilation_id = mapped_column(String(51), nullable=False)
ReplayTicketRecord.budget_reservation_id = mapped_column(String(51), nullable=False)
ReplayTicketRecord.rate_reservation_id = mapped_column(String(49), nullable=False)
_replay_ticket_table.append_constraint(
    ForeignKeyConstraint(
        [
            "compilation_id",
            "item_id",
            "batch_id",
            "replay_run_id",
            "compilation_digest",
            "grant_digest",
        ],
        [
            "cp_replay_compilations.compilation_id",
            "cp_replay_compilations.item_id",
            "cp_replay_compilations.batch_id",
            "cp_replay_compilations.replay_run_id",
            "cp_replay_compilations.compilation_digest",
            "cp_replay_compilations.grant_digest",
        ],
        name="fk_cp_replay_tickets_compilation_authority",
        ondelete="RESTRICT",
    )
)
_replay_ticket_table.append_constraint(
    UniqueConstraint(
        "compilation_id",
        name="uq_cp_replay_tickets_compilation",
    )
)


class ReplayBudgetAccountRecord(Base):
    """Mutable Campaign Tool-call counters serialized before Replay issuance."""

    __tablename__ = "cp_replay_budget_accounts"
    __table_args__ = (
        CheckConstraint(
            "length(budget_account_id) = 54 AND "
            "substr(budget_account_id, 1, 22) = 'replay-budget-account_' AND "
            + _lower_hex_check("substr(budget_account_id, 23, 32)", 32),
            name="ck_cp_replay_budget_accounts_id",
        ),
        CheckConstraint(
            _lower_hex_check("source_root_digest", 64),
            name="ck_cp_replay_budget_accounts_source_root",
        ),
        CheckConstraint(
            _lower_hex_check("budget_digest", 64),
            name="ck_cp_replay_budget_accounts_budget_digest",
        ),
        CheckConstraint(
            "length(campaign_name) > 0 AND length(campaign_name) <= 128",
            name="ck_cp_replay_budget_accounts_campaign",
        ),
        CheckConstraint(
            "max_tool_calls > 0 AND max_tool_calls <= 1000000",
            name="ck_cp_replay_budget_accounts_max_calls",
        ),
        CheckConstraint(
            "baseline_used_calls >= 0 AND reserved_calls >= 0 AND consumed_calls >= 0 "
            "AND released_calls >= 0 "
            "AND baseline_used_calls + reserved_calls + consumed_calls <= max_tool_calls",
            name="ck_cp_replay_budget_accounts_usage",
        ),
        CheckConstraint("cas_version > 0", name="ck_cp_replay_budget_accounts_cas"),
        UniqueConstraint("source_run_id", name="uq_cp_replay_budget_accounts_source_run"),
        UniqueConstraint(
            "budget_account_id",
            "source_run_id",
            "source_root_digest",
            name="uq_cp_replay_budget_accounts_authority",
        ),
    )

    budget_account_id: Mapped[str] = mapped_column(String(54), primary_key=True)
    source_run_id: Mapped[str] = mapped_column(
        ForeignKey("cp_runs.run_id", ondelete="RESTRICT"), nullable=False
    )
    source_root_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    campaign_name: Mapped[str] = mapped_column(String(128), nullable=False)
    budget_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    max_tool_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    baseline_used_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    reserved_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    consumed_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    released_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    cas_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ReplayRateAccountRecord(Base):
    """Campaign rolling-window authority sealed from the source ledger snapshot."""

    __tablename__ = "cp_replay_rate_accounts"
    __table_args__ = (
        CheckConstraint(
            "length(rate_account_id) = 52 AND "
            "substr(rate_account_id, 1, 20) = 'replay-rate-account_' AND "
            + _lower_hex_check("substr(rate_account_id, 21, 32)", 32),
            name="ck_cp_replay_rate_accounts_id",
        ),
        CheckConstraint(
            _lower_hex_check("source_root_digest", 64),
            name="ck_cp_replay_rate_accounts_source_root",
        ),
        CheckConstraint(
            _lower_hex_check("rate_limits_digest", 64),
            name="ck_cp_replay_rate_accounts_rate_digest",
        ),
        CheckConstraint(
            "length(campaign_name) > 0 AND length(campaign_name) <= 128",
            name="ck_cp_replay_rate_accounts_campaign",
        ),
        CheckConstraint(
            "length(ledger_id) = 44 AND substr(ledger_id, 1, 12) = 'rate-ledger_' AND "
            + _lower_hex_check("substr(ledger_id, 13, 32)", 32),
            name="ck_cp_replay_rate_accounts_ledger",
        ),
        CheckConstraint(
            "max_requests_per_minute IS NULL OR "
            "(max_requests_per_minute > 0 AND max_requests_per_minute <= 60000)",
            name="ck_cp_replay_rate_accounts_max_requests",
        ),
        CheckConstraint(
            "observed_request_units >= 0 AND "
            "(max_requests_per_minute IS NULL OR "
            "observed_request_units <= max_requests_per_minute)",
            name="ck_cp_replay_rate_accounts_observed_units",
        ),
        CheckConstraint("window_seconds = 60", name="ck_cp_replay_rate_accounts_window"),
        CheckConstraint("cas_version > 0", name="ck_cp_replay_rate_accounts_cas"),
        UniqueConstraint("source_run_id", name="uq_cp_replay_rate_accounts_source_run"),
        UniqueConstraint(
            "rate_account_id",
            "source_run_id",
            "source_root_digest",
            name="uq_cp_replay_rate_accounts_authority",
        ),
    )

    rate_account_id: Mapped[str] = mapped_column(String(52), primary_key=True)
    source_run_id: Mapped[str] = mapped_column(
        ForeignKey("cp_runs.run_id", ondelete="RESTRICT"), nullable=False
    )
    source_root_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    campaign_name: Mapped[str] = mapped_column(String(128), nullable=False)
    rate_limits_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    ledger_id: Mapped[str] = mapped_column(String(44), nullable=False)
    max_requests_per_minute: Mapped[int | None] = mapped_column(Integer)
    observed_request_units: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    cas_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ReplayBudgetReservationRecord(Base):
    """Mutable accounting lifecycle for one ticket's Tool-call reservation."""

    __tablename__ = "cp_replay_budget_reservations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["item_id", "batch_id"],
            ["cp_replay_items.item_id", "cp_replay_items.batch_id"],
            name="fk_cp_replay_budget_reservations_item",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "compilation_id",
                "item_id",
                "batch_id",
            ],
            [
                "cp_replay_compilations.compilation_id",
                "cp_replay_compilations.item_id",
                "cp_replay_compilations.batch_id",
            ],
            name="fk_cp_replay_budget_reservations_compilation",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "length(budget_reservation_id) = 51 AND "
            "substr(budget_reservation_id, 1, 19) = 'budget-reservation_' AND "
            + _lower_hex_check("substr(budget_reservation_id, 20, 32)", 32),
            name="ck_cp_replay_budget_reservations_id",
        ),
        CheckConstraint("attempt_number > 0", name="ck_cp_replay_budget_reservations_attempt"),
        CheckConstraint(
            "state IN ('active', 'consumed', 'released')",
            name="ck_cp_replay_budget_reservations_state",
        ),
        CheckConstraint(
            "total_calls > 0 AND consumed_calls >= 0 AND released_calls >= 0 "
            "AND consumed_calls + released_calls <= total_calls",
            name="ck_cp_replay_budget_reservations_usage",
        ),
        CheckConstraint(
            "(state = 'active' AND released_at IS NULL "
            "AND consumed_calls < total_calls AND released_calls = 0) "
            "OR (state = 'consumed' AND released_at IS NULL "
            "AND consumed_calls = total_calls AND released_calls = 0) "
            "OR (state = 'released' AND released_at IS NOT NULL "
            "AND consumed_calls + released_calls = total_calls)",
            name="ck_cp_replay_budget_reservations_lifecycle",
        ),
        UniqueConstraint(
            "item_id",
            "attempt_number",
            name="uq_cp_replay_budget_reservations_item_attempt",
        ),
        UniqueConstraint(
            "compilation_id",
            name="uq_cp_replay_budget_reservations_compilation",
        ),
        UniqueConstraint(
            "budget_reservation_id",
            "item_id",
            "batch_id",
            "attempt_number",
            "compilation_id",
            name="uq_cp_replay_budget_reservations_ticket_authority",
        ),
        Index("ix_cp_replay_budget_reservations_account_state", "budget_account_id", "state"),
    )

    budget_reservation_id: Mapped[str] = mapped_column(String(51), primary_key=True)
    budget_account_id: Mapped[str] = mapped_column(
        ForeignKey("cp_replay_budget_accounts.budget_account_id", ondelete="RESTRICT"),
        nullable=False,
    )
    item_id: Mapped[str] = mapped_column(String(80), nullable=False)
    batch_id: Mapped[str] = mapped_column(String(80), nullable=False)
    compilation_id: Mapped[str] = mapped_column(String(51), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    total_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    consumed_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    released_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReplayRateReservationRecord(Base):
    """Mutable rolling-window request-unit reservation for one ticket attempt."""

    __tablename__ = "cp_replay_rate_reservations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["item_id", "batch_id"],
            ["cp_replay_items.item_id", "cp_replay_items.batch_id"],
            name="fk_cp_replay_rate_reservations_item",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "compilation_id",
                "item_id",
                "batch_id",
            ],
            [
                "cp_replay_compilations.compilation_id",
                "cp_replay_compilations.item_id",
                "cp_replay_compilations.batch_id",
            ],
            name="fk_cp_replay_rate_reservations_compilation",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "length(rate_reservation_id) = 49 AND "
            "substr(rate_reservation_id, 1, 17) = 'rate-reservation_' AND "
            + _lower_hex_check("substr(rate_reservation_id, 18, 32)", 32),
            name="ck_cp_replay_rate_reservations_id",
        ),
        CheckConstraint("attempt_number > 0", name="ck_cp_replay_rate_reservations_attempt"),
        CheckConstraint(
            "state IN ('active', 'consumed', 'released')",
            name="ck_cp_replay_rate_reservations_state",
        ),
        CheckConstraint(
            "total_request_units > 0 AND consumed_request_units >= 0 "
            "AND released_request_units >= 0 "
            "AND consumed_request_units + released_request_units <= total_request_units",
            name="ck_cp_replay_rate_reservations_usage",
        ),
        CheckConstraint(
            "(state = 'active' AND released_at IS NULL "
            "AND consumed_request_units < total_request_units "
            "AND released_request_units = 0) "
            "OR (state = 'consumed' AND released_at IS NULL "
            "AND consumed_request_units = total_request_units "
            "AND released_request_units = 0) "
            "OR (state = 'released' AND released_at IS NOT NULL "
            "AND consumed_request_units + released_request_units = total_request_units)",
            name="ck_cp_replay_rate_reservations_lifecycle",
        ),
        CheckConstraint(
            "expires_at > reserved_at",
            name="ck_cp_replay_rate_reservations_expiry",
        ),
        UniqueConstraint(
            "item_id",
            "attempt_number",
            name="uq_cp_replay_rate_reservations_item_attempt",
        ),
        UniqueConstraint(
            "compilation_id",
            name="uq_cp_replay_rate_reservations_compilation",
        ),
        UniqueConstraint(
            "rate_reservation_id",
            "item_id",
            "batch_id",
            "attempt_number",
            "compilation_id",
            name="uq_cp_replay_rate_reservations_ticket_authority",
        ),
        Index("ix_cp_replay_rate_reservations_account_window", "rate_account_id", "expires_at"),
    )

    rate_reservation_id: Mapped[str] = mapped_column(String(49), primary_key=True)
    rate_account_id: Mapped[str] = mapped_column(
        ForeignKey("cp_replay_rate_accounts.rate_account_id", ondelete="RESTRICT"),
        nullable=False,
    )
    item_id: Mapped[str] = mapped_column(String(80), nullable=False)
    batch_id: Mapped[str] = mapped_column(String(80), nullable=False)
    compilation_id: Mapped[str] = mapped_column(String(51), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    total_request_units: Mapped[int] = mapped_column(Integer, nullable=False)
    consumed_request_units: Mapped[int] = mapped_column(Integer, nullable=False)
    released_request_units: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    reserved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


_replay_ticket_table.append_constraint(
    ForeignKeyConstraint(
        [
            "budget_reservation_id",
            "item_id",
            "batch_id",
            "attempt_number",
            "compilation_id",
        ],
        [
            "cp_replay_budget_reservations.budget_reservation_id",
            "cp_replay_budget_reservations.item_id",
            "cp_replay_budget_reservations.batch_id",
            "cp_replay_budget_reservations.attempt_number",
            "cp_replay_budget_reservations.compilation_id",
        ],
        name="fk_cp_replay_tickets_budget_reservation",
        ondelete="RESTRICT",
    )
)
_replay_ticket_table.append_constraint(
    ForeignKeyConstraint(
        [
            "rate_reservation_id",
            "item_id",
            "batch_id",
            "attempt_number",
            "compilation_id",
        ],
        [
            "cp_replay_rate_reservations.rate_reservation_id",
            "cp_replay_rate_reservations.item_id",
            "cp_replay_rate_reservations.batch_id",
            "cp_replay_rate_reservations.attempt_number",
            "cp_replay_rate_reservations.compilation_id",
        ],
        name="fk_cp_replay_tickets_rate_reservation",
        ondelete="RESTRICT",
    )
)
_replay_ticket_table.append_constraint(
    UniqueConstraint(
        "budget_reservation_id",
        name="uq_cp_replay_tickets_budget_reservation",
    )
)
_replay_ticket_table.append_constraint(
    UniqueConstraint(
        "rate_reservation_id",
        name="uq_cp_replay_tickets_rate_reservation",
    )
)


def _build_v5_metadata() -> MetaData:
    """Freeze the exact schema-v5 metadata before Tool-call permits are attached."""

    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name in V5_CONTROL_PLANE_TABLES:
            table.to_metadata(metadata)
    return metadata


_V5_METADATA = _build_v5_metadata()


_REPLAY_TICKET_PERMIT_AUTHORITY_COLUMNS = (
    "ticket_id",
    "item_id",
    "batch_id",
    "job_id",
    "replay_run_id",
    "compilation_id",
    "budget_reservation_id",
    "rate_reservation_id",
    "attempt_number",
    "fencing_value",
    "claim_principal",
    "executor_profile",
    "lease_token_hash",
    "source_root_digest",
    "compilation_digest",
    "grant_digest",
)
_replay_ticket_permit_authority_index = Index(
    "ux_cp_replay_tickets_tool_permit_authority",
    *(
        _replay_ticket_table.c[column_name]
        for column_name in _REPLAY_TICKET_PERMIT_AUTHORITY_COLUMNS
    ),
    unique=True,
)


class ReplayToolPermitRecord(Base):
    """Append-only proof that one exact Replay Tool call consumed its reservation."""

    __tablename__ = "cp_replay_tool_permits"
    __table_args__ = (
        ForeignKeyConstraint(
            [
                "ticket_id",
                "item_id",
                "batch_id",
                "job_id",
                "replay_run_id",
                "compilation_id",
                "budget_reservation_id",
                "rate_reservation_id",
                "attempt_number",
                "fencing_value",
                "issued_to",
                "executor_profile",
                "lease_token_hash",
                "source_root_digest",
                "compilation_digest",
                "grant_digest",
            ],
            [
                "cp_replay_tickets.ticket_id",
                "cp_replay_tickets.item_id",
                "cp_replay_tickets.batch_id",
                "cp_replay_tickets.job_id",
                "cp_replay_tickets.replay_run_id",
                "cp_replay_tickets.compilation_id",
                "cp_replay_tickets.budget_reservation_id",
                "cp_replay_tickets.rate_reservation_id",
                "cp_replay_tickets.attempt_number",
                "cp_replay_tickets.fencing_value",
                "cp_replay_tickets.claim_principal",
                "cp_replay_tickets.executor_profile",
                "cp_replay_tickets.lease_token_hash",
                "cp_replay_tickets.source_root_digest",
                "cp_replay_tickets.compilation_digest",
                "cp_replay_tickets.grant_digest",
            ],
            name="fk_cp_replay_tool_permits_ticket_binding",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "compilation_id",
                "item_id",
                "batch_id",
                "replay_run_id",
                "compilation_digest",
                "grant_digest",
            ],
            [
                "cp_replay_compilations.compilation_id",
                "cp_replay_compilations.item_id",
                "cp_replay_compilations.batch_id",
                "cp_replay_compilations.replay_run_id",
                "cp_replay_compilations.compilation_digest",
                "cp_replay_compilations.grant_digest",
            ],
            name="fk_cp_replay_tool_permits_compilation_authority",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "budget_reservation_id",
                "item_id",
                "batch_id",
                "attempt_number",
                "compilation_id",
            ],
            [
                "cp_replay_budget_reservations.budget_reservation_id",
                "cp_replay_budget_reservations.item_id",
                "cp_replay_budget_reservations.batch_id",
                "cp_replay_budget_reservations.attempt_number",
                "cp_replay_budget_reservations.compilation_id",
            ],
            name="fk_cp_replay_tool_permits_budget_reservation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "rate_reservation_id",
                "item_id",
                "batch_id",
                "attempt_number",
                "compilation_id",
            ],
            [
                "cp_replay_rate_reservations.rate_reservation_id",
                "cp_replay_rate_reservations.item_id",
                "cp_replay_rate_reservations.batch_id",
                "cp_replay_rate_reservations.attempt_number",
                "cp_replay_rate_reservations.compilation_id",
            ],
            name="fk_cp_replay_tool_permits_rate_reservation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["batch_id", "source_root_digest"],
            ["cp_replay_batches.batch_id", "cp_replay_batches.source_root_digest"],
            name="fk_cp_replay_tool_permits_batch_root",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "length(permit_id) = 46 AND substr(permit_id, 1, 14) = 'replay-permit_' AND "
            + _lower_hex_check("substr(permit_id, 15, 32)", 32),
            name="ck_cp_replay_tool_permits_id",
        ),
        CheckConstraint(
            _lower_hex_check("permit_digest", 64),
            name="ck_cp_replay_tool_permits_digest",
        ),
        CheckConstraint(
            "length(replay_request_id) = 44 "
            "AND substr(replay_request_id, 1, 12) = 'tool_replay_' AND "
            + _lower_hex_check("substr(replay_request_id, 13, 32)", 32),
            name="ck_cp_replay_tool_permits_request_id",
        ),
        CheckConstraint(
            "attempt_number > 0 AND attempt_number <= 100",
            name="ck_cp_replay_tool_permits_attempt",
        ),
        CheckConstraint("fencing_value > 0", name="ck_cp_replay_tool_permits_fence"),
        CheckConstraint(
            "call_ordinal > 0 AND call_ordinal <= 20",
            name="ck_cp_replay_tool_permits_ordinal",
        ),
        CheckConstraint(
            "length(issued_to) > 0 AND length(issued_to) <= 200 "
            "AND length(executor_profile) > 0 AND length(executor_profile) <= 200",
            name="ck_cp_replay_tool_permits_principal",
        ),
        CheckConstraint(
            _lower_hex_check("lease_token_hash", 64),
            name="ck_cp_replay_tool_permits_lease_hash",
        ),
        CheckConstraint(
            _lower_hex_check("source_root_digest", 64),
            name="ck_cp_replay_tool_permits_source_root",
        ),
        CheckConstraint(
            _lower_hex_check("compilation_digest", 64),
            name="ck_cp_replay_tool_permits_compilation_digest",
        ),
        CheckConstraint(
            _lower_hex_check("grant_digest", 64),
            name="ck_cp_replay_tool_permits_grant_digest",
        ),
        CheckConstraint(
            "length(original_request_id) > 0 AND length(original_request_id) <= 200",
            name="ck_cp_replay_tool_permits_original_request",
        ),
        CheckConstraint(
            "length(tool_id) > 0 AND length(tool_id) <= 200 "
            "AND length(tool_version) > 0 AND length(tool_version) <= 100",
            name="ck_cp_replay_tool_permits_tool",
        ),
        CheckConstraint(
            "length(target_id) > 0 AND length(target_id) <= 200 "
            "AND length(target) > 0 AND length(target) <= 2000",
            name="ck_cp_replay_tool_permits_target",
        ),
        CheckConstraint(
            "length(method) > 0 AND length(method) <= 20",
            name="ck_cp_replay_tool_permits_method",
        ),
        CheckConstraint(
            _lower_hex_check("compiled_argument_digest", 64),
            name="ck_cp_replay_tool_permits_argument_digest",
        ),
        CheckConstraint(
            "tool_call_units = 1 AND request_units > 0 AND request_units <= 100",
            name="ck_cp_replay_tool_permits_units",
        ),
        CheckConstraint(
            "expires_at > issued_at AND rate_window_expires_at > issued_at",
            name="ck_cp_replay_tool_permits_expiry",
        ),
        UniqueConstraint("permit_digest", name="uq_cp_replay_tool_permits_digest"),
        UniqueConstraint("replay_request_id", name="uq_cp_replay_tool_permits_request_id"),
        UniqueConstraint(
            "ticket_id",
            "call_ordinal",
            name="uq_cp_replay_tool_permits_ticket_ordinal",
        ),
        UniqueConstraint(
            "permit_id",
            "ticket_id",
            "call_ordinal",
            name="uq_cp_replay_tool_permits_binding",
        ),
        Index(
            "ix_cp_replay_tool_permits_ticket_time",
            "ticket_id",
            "issued_at",
        ),
        Index(
            "ix_cp_replay_tool_permits_rate_window",
            "rate_reservation_id",
            "rate_window_expires_at",
        ),
    )

    permit_id: Mapped[str] = mapped_column(String(46), primary_key=True)
    permit_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    replay_request_id: Mapped[str] = mapped_column(String(44), nullable=False)
    job_id: Mapped[str] = mapped_column(String(64), nullable=False)
    batch_id: Mapped[str] = mapped_column(String(80), nullable=False)
    item_id: Mapped[str] = mapped_column(String(80), nullable=False)
    ticket_id: Mapped[str] = mapped_column(String(80), nullable=False)
    compilation_id: Mapped[str] = mapped_column(String(51), nullable=False)
    budget_reservation_id: Mapped[str] = mapped_column(String(51), nullable=False)
    rate_reservation_id: Mapped[str] = mapped_column(String(49), nullable=False)
    replay_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    fencing_value: Mapped[int] = mapped_column(Integer, nullable=False)
    call_ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    issued_to: Mapped[str] = mapped_column(String(200), nullable=False)
    executor_profile: Mapped[str] = mapped_column(String(200), nullable=False)
    lease_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_root_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    compilation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    grant_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    original_request_id: Mapped[str] = mapped_column(String(200), nullable=False)
    tool_id: Mapped[str] = mapped_column(String(200), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(100), nullable=False)
    target_id: Mapped[str] = mapped_column(String(200), nullable=False)
    target: Mapped[str] = mapped_column(String(2_000), nullable=False)
    method: Mapped[str] = mapped_column(String(20), nullable=False)
    compiled_argument_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_call_units: Mapped[int] = mapped_column(Integer, nullable=False)
    request_units: Mapped[int] = mapped_column(Integer, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rate_window_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


def _build_v6_metadata() -> MetaData:
    """Freeze the exact schema-v6 metadata before execution context is attached."""

    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name in V6_CONTROL_PLANE_TABLES:
            table.to_metadata(metadata)
    return metadata


_V6_METADATA = _build_v6_metadata()


class ReplayExecutionContextRecord(Base):
    """Append-only Worker execution context bound one-to-one to a compilation."""

    __tablename__ = "cp_replay_execution_contexts"
    __table_args__ = (
        ForeignKeyConstraint(
            [
                "compilation_id",
                "item_id",
                "batch_id",
                "replay_run_id",
                "compilation_digest",
                "grant_digest",
            ],
            [
                "cp_replay_compilations.compilation_id",
                "cp_replay_compilations.item_id",
                "cp_replay_compilations.batch_id",
                "cp_replay_compilations.replay_run_id",
                "cp_replay_compilations.compilation_digest",
                "cp_replay_compilations.grant_digest",
            ],
            name="fk_cp_replay_execution_contexts_compilation_authority",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "length(context_id) = 47 "
            "AND substr(context_id, 1, 15) = 'replay-context_' AND "
            + _lower_hex_check("substr(context_id, 16, 32)", 32),
            name="ck_cp_replay_execution_contexts_id",
        ),
        CheckConstraint(
            _lower_hex_check("context_digest", 64),
            name="ck_cp_replay_execution_contexts_digest",
        ),
        CheckConstraint(
            "byte_length > 0 AND byte_length <= 2147483647 "
            "AND length(canonical_context) = byte_length",
            name="ck_cp_replay_execution_contexts_canonical_bytes",
        ),
        CheckConstraint(
            "length(required_executor_profile) > 0 "
            "AND length(required_executor_profile) <= 200 AND "
            + _allowed_characters_check(
                "required_executor_profile",
                _ASCII_ALPHANUMERIC + "._:-",
            )
            + " AND "
            + _allowed_characters_check(
                "substr(required_executor_profile, 1, 1)",
                _ASCII_ALPHANUMERIC,
            ),
            name="ck_cp_replay_execution_contexts_executor_profile",
        ),
        CheckConstraint(
            "length(output_staging_id) = 38 "
            "AND substr(output_staging_id, 1, 6) = 'stage_' AND "
            + _lower_hex_check("substr(output_staging_id, 7, 32)", 32),
            name="ck_cp_replay_execution_contexts_output_staging_id",
        ),
        UniqueConstraint(
            "compilation_id",
            name="uq_cp_replay_execution_contexts_compilation",
        ),
        UniqueConstraint(
            "context_digest",
            name="uq_cp_replay_execution_contexts_digest",
        ),
        UniqueConstraint(
            "output_staging_id",
            name="uq_cp_replay_execution_contexts_output_staging_id",
        ),
        Index("ix_cp_replay_execution_contexts_batch", "batch_id", "created_at"),
        Index("ix_cp_replay_execution_contexts_item", "item_id", "created_at"),
    )

    context_id: Mapped[str] = mapped_column(String(47), primary_key=True)
    compilation_id: Mapped[str] = mapped_column(String(51), nullable=False)
    item_id: Mapped[str] = mapped_column(String(80), nullable=False)
    batch_id: Mapped[str] = mapped_column(String(80), nullable=False)
    replay_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    compilation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    grant_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    context_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_context: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    byte_length: Mapped[int] = mapped_column(Integer, nullable=False)
    required_executor_profile: Mapped[str] = mapped_column(String(200), nullable=False)
    output_staging_id: Mapped[str] = mapped_column(String(38), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def _build_v7_metadata() -> MetaData:
    """Freeze schema v7 before v8 adds only complete append-only guards."""

    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name in V7_CONTROL_PLANE_TABLES:
            table.to_metadata(metadata)
    return metadata


_V7_METADATA = _build_v7_metadata()


def _install_parser_safe_checks(metadata: MetaData) -> None:
    """Install equivalent character checks with bounded SQLite parser depth."""

    replacements = {
        "ck_cp_artifacts_sealed_run_id": (
            "length(sealed_run_id) > 0 AND length(sealed_run_id) <= 64 AND "
            + _balanced_allowed_characters_check(
                "substr(sealed_run_id, 1, 1)",
                _ASCII_ALPHANUMERIC,
            )
            + " AND "
            + _balanced_allowed_characters_check(
                "sealed_run_id",
                _ASCII_ALPHANUMERIC + "._:-",
            )
        ),
        "ck_cp_artifacts_media_type": (
            "length(media_type) >= 3 AND length(media_type) <= 200 AND "
            + _balanced_allowed_characters_check(
                "substr(media_type, 1, 1)",
                _ASCII_ALPHANUMERIC,
            )
            + " AND "
            + _balanced_allowed_characters_check(
                "media_type",
                _ASCII_ALPHANUMERIC + ".+-/",
            )
            + " AND length(media_type) = length(replace(media_type, '/', '')) + 1 "
            "AND substr(media_type, length(media_type), 1) <> '/' "
            "AND length(replace(media_type, '/.', '')) = length(media_type) "
            "AND length(replace(media_type, '/+', '')) = length(media_type) "
            "AND length(replace(media_type, '/-', '')) = length(media_type)"
        ),
        "ck_cp_artifacts_schema_kind": (
            "length(schema_kind) > 0 AND length(schema_kind) <= 200 AND "
            + _balanced_allowed_characters_check(
                "substr(schema_kind, 1, 1)",
                _ASCII_ALPHANUMERIC,
            )
            + " AND "
            + _balanced_allowed_characters_check(
                "schema_kind",
                _ASCII_ALPHANUMERIC + "._:-",
            )
        ),
        "ck_cp_replay_execution_contexts_executor_profile": (
            "length(required_executor_profile) > 0 "
            "AND length(required_executor_profile) <= 200 AND "
            + _balanced_allowed_characters_check(
                "required_executor_profile",
                _ASCII_ALPHANUMERIC + "._:-",
            )
            + " AND "
            + _balanced_allowed_characters_check(
                "substr(required_executor_profile, 1, 1)",
                _ASCII_ALPHANUMERIC,
            )
        ),
    }
    for table_name in ("cp_artifacts", "cp_replay_execution_contexts"):
        table = metadata.tables.get(table_name)
        if table is None:
            continue
        for constraint in table.constraints:
            replacement = replacements.get(str(constraint.name))
            if replacement is not None and isinstance(constraint, CheckConstraint):
                constraint.sqltext = text(replacement)


def _parser_safe_metadata_copy(metadata: MetaData) -> MetaData:
    """Copy historical metadata without emitting parser-deep SQLite checks."""

    parser_safe = MetaData()
    for table in metadata.sorted_tables:
        table.to_metadata(parser_safe)
    _install_parser_safe_checks(parser_safe)
    return parser_safe


_install_parser_safe_checks(Base.metadata)


class ReplayFinalizationRecord(Base):
    """Append-only server-derived proof of one atomically finalized Replay."""

    __tablename__ = "cp_replay_finalizations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["ticket_id", "item_id", "batch_id", "job_id", "replay_run_id"],
            [
                "cp_replay_tickets.ticket_id",
                "cp_replay_tickets.item_id",
                "cp_replay_tickets.batch_id",
                "cp_replay_tickets.job_id",
                "cp_replay_tickets.replay_run_id",
            ],
            name="fk_cp_replay_finalizations_ticket_binding",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["artifact_id", "repository_version"],
            ["cp_artifacts.artifact_id", "cp_artifacts.repository_version"],
            name="fk_cp_replay_finalizations_artifact",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "length(finalization_id) = 52 "
            "AND substr(finalization_id, 1, 20) = 'replay-finalization_' AND "
            + _lower_hex_check("substr(finalization_id, 21, 32)", 32),
            name="ck_cp_replay_finalizations_id",
        ),
        CheckConstraint(
            "length(ticket_id) = 46 "
            "AND substr(ticket_id, 1, 14) = 'replay-ticket_' AND "
            + _lower_hex_check("substr(ticket_id, 15, 32)", 32),
            name="ck_cp_replay_finalizations_ticket_id",
        ),
        CheckConstraint(
            "attempt_number > 0 AND attempt_number <= 100 AND fencing_value > 0",
            name="ck_cp_replay_finalizations_attempt_fence",
        ),
        CheckConstraint(
            "length(output_staging_id) = 38 "
            "AND substr(output_staging_id, 1, 6) = 'stage_' AND "
            + _lower_hex_check("substr(output_staging_id, 7, 32)", 32),
            name="ck_cp_replay_finalizations_staging_id",
        ),
        CheckConstraint(
            _lower_hex_check("artifact_set_digest", 64),
            name="ck_cp_replay_finalizations_artifact_set_digest",
        ),
        CheckConstraint(
            _lower_hex_check("artifact_seal_root_digest", 64),
            name="ck_cp_replay_finalizations_artifact_seal",
        ),
        CheckConstraint(
            _lower_hex_check("receipt_seal_root_digest", 64),
            name="ck_cp_replay_finalizations_receipt_seal",
        ),
        CheckConstraint(
            _lower_hex_check("gate_decision_digest", 64),
            name="ck_cp_replay_finalizations_gate_digest",
        ),
        CheckConstraint(
            _lower_hex_check("result_digest", 64),
            name="ck_cp_replay_finalizations_result_digest",
        ),
        CheckConstraint(
            "length(finalized_by) > 0 AND length(finalized_by) <= 200",
            name="ck_cp_replay_finalizations_actor",
        ),
        UniqueConstraint("ticket_id", name="uq_cp_replay_finalizations_ticket"),
        UniqueConstraint(
            "artifact_id",
            "repository_version",
            name="uq_cp_replay_finalizations_artifact",
        ),
        UniqueConstraint("result_digest", name="uq_cp_replay_finalizations_result"),
        Index("ix_cp_replay_finalizations_batch_time", "batch_id", "finalized_at"),
    )

    finalization_id: Mapped[str] = mapped_column(String(52), primary_key=True)
    ticket_id: Mapped[str] = mapped_column(String(80), nullable=False)
    batch_id: Mapped[str] = mapped_column(String(80), nullable=False)
    item_id: Mapped[str] = mapped_column(String(80), nullable=False)
    job_id: Mapped[str] = mapped_column(String(64), nullable=False)
    replay_run_id: Mapped[str] = mapped_column(String(64), nullable=False)
    compilation_id: Mapped[str] = mapped_column(String(51), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    fencing_value: Mapped[int] = mapped_column(Integer, nullable=False)
    output_staging_id: Mapped[str] = mapped_column(String(38), nullable=False)
    artifact_id: Mapped[str] = mapped_column(String(41), nullable=False)
    repository_version: Mapped[int] = mapped_column(Integer, nullable=False)
    artifact_set_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_seal_root_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    receipt_seal_root_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    gate_decision: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    gate_decision_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    result_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    finalized_by: Mapped[str] = mapped_column(String(200), nullable=False)
    finalized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def _build_v9_metadata() -> MetaData:
    """Freeze the exact schema-v9 layout before v10 adds core authority columns."""

    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name in V10_CONTROL_PLANE_TABLES:
            table.to_metadata(metadata)
    return metadata


_V9_METADATA = _build_v9_metadata()

RunRecord.submission_authority_digest = mapped_column(String(64))
JobRecord.submission_authority_digest = mapped_column(String(64))
JobRecord.lease_deadline_at = mapped_column(DateTime(timezone=True))
JobRecord.heartbeat_event_at = mapped_column(DateTime(timezone=True))


def _build_v10_metadata() -> MetaData:
    """Freeze schema v10 before the projection publication authority is added."""

    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name in V10_CONTROL_PLANE_TABLES:
            table.to_metadata(metadata)
    return metadata


_V10_METADATA = _build_v10_metadata()


class ReplayProjectionRecord(Base):
    """Append-only publication authority for one versioned batch projection."""

    __tablename__ = "cp_replay_projections"
    __table_args__ = (
        ForeignKeyConstraint(
            ["batch_id", "source_root_digest"],
            ["cp_replay_batches.batch_id", "cp_replay_batches.source_root_digest"],
            name="fk_cp_replay_projections_batch_root",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["artifact_id", "repository_version"],
            ["cp_artifacts.artifact_id", "cp_artifacts.repository_version"],
            name="fk_cp_replay_projections_artifact",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "length(projection_id) = 50 "
            "AND substr(projection_id, 1, 18) = 'replay-projection_' AND "
            + _lower_hex_check("substr(projection_id, 19, 32)", 32),
            name="ck_cp_replay_projections_id",
        ),
        CheckConstraint(
            _lower_hex_check("source_root_digest", 64),
            name="ck_cp_replay_projections_source_root",
        ),
        CheckConstraint(
            "batch_cas_version > 0",
            name="ck_cp_replay_projections_batch_cas",
        ),
        CheckConstraint(
            _lower_hex_check("input_authority_digest", 64),
            name="ck_cp_replay_projections_input_digest",
        ),
        CheckConstraint(
            "length(published_by) > 0 AND length(published_by) <= 200",
            name="ck_cp_replay_projections_actor",
        ),
        UniqueConstraint("batch_id", name="uq_cp_replay_projections_batch"),
        UniqueConstraint(
            "artifact_id",
            "repository_version",
            name="uq_cp_replay_projections_artifact",
        ),
        UniqueConstraint(
            "input_authority_digest",
            name="uq_cp_replay_projections_input_digest",
        ),
        Index("ix_cp_replay_projections_time", "published_at"),
    )

    projection_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(80), nullable=False)
    source_root_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_id: Mapped[str] = mapped_column(String(41), nullable=False)
    repository_version: Mapped[int] = mapped_column(Integer, nullable=False)
    batch_cas_version: Mapped[int] = mapped_column(Integer, nullable=False)
    input_authority: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    input_authority_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    published_by: Mapped[str] = mapped_column(String(200), nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def _build_v11_metadata() -> MetaData:
    """Freeze schema v11 before parent Retest source authority is added."""

    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        if table.name in V11_CONTROL_PLANE_TABLES:
            table.to_metadata(metadata)
    return metadata


_V11_METADATA = _build_v11_metadata()


class ReplayRetestSourceRecord(Base):
    """Append-only parent Retest Artifact bound to one negative Replay batch."""

    __tablename__ = "cp_replay_retest_sources"
    __table_args__ = (
        ForeignKeyConstraint(
            ["artifact_id", "repository_version"],
            ["cp_artifacts.artifact_id", "cp_artifacts.repository_version"],
            name="fk_cp_replay_retest_sources_artifact",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "repository_version > 0",
            name="ck_cp_replay_retest_sources_repository_version",
        ),
        UniqueConstraint(
            "artifact_id",
            "repository_version",
            "batch_id",
            name="uq_cp_replay_retest_sources_authority",
        ),
        Index("ix_cp_replay_retest_sources_artifact", "artifact_id", "repository_version"),
    )

    batch_id: Mapped[str] = mapped_column(
        ForeignKey("cp_replay_batches.batch_id", ondelete="RESTRICT"),
        primary_key=True,
    )
    artifact_id: Mapped[str] = mapped_column(String(41), nullable=False)
    repository_version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
