"""SQLAlchemy schema and transaction boundary for the durable Control Plane."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

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
    create_engine,
    event,
    func,
    inspect,
    select,
    text,
)
from sqlalchemy.engine import Connection
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

LEGACY_SCHEMA_VERSION = 1
REPLAY_AUTHORITY_SCHEMA_VERSION = 2
ARTIFACT_AUTHORITY_SCHEMA_VERSION = 3
CURRENT_SCHEMA_VERSION = 4

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
CURRENT_CONTROL_PLANE_TABLES = frozenset(
    {*V3_CONTROL_PLANE_TABLES, *REPLAY_COMPILATION_AUTHORITY_TABLES}
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


class SchemaInitializationError(RuntimeError):
    """The durable Control Plane schema is unknown, partial, or corrupted."""


def utc_now() -> datetime:
    return datetime.now(UTC)


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


class ControlPlaneRepository:
    """Own the database engine and expose short, explicit transaction scopes."""

    def __init__(self, database_url: str, *, echo: bool = False) -> None:
        if database_url.startswith("sqlite:///"):
            raw_path = database_url.removeprefix("sqlite:///")
            if raw_path != ":memory:":
                Path(raw_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        connect_args: dict[str, object] = {}
        if database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        self.engine = create_engine(
            database_url,
            echo=echo,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        if database_url.startswith("sqlite"):
            event.listen(self.engine, "connect", _enable_sqlite_foreign_keys)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @property
    def dialect_name(self) -> str:
        return self.engine.dialect.name

    @contextmanager
    def transaction(self) -> Iterator[Session]:
        with self._sessions.begin() as session:
            yield session

    def initialize(self) -> None:
        """Initialize or migrate a recognized schema, failing closed on any drift."""

        if self.dialect_name == "sqlite":
            with self.engine.connect() as connection:
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                try:
                    _initialize_schema(connection)
                except BaseException:
                    connection.rollback()
                    raise
                connection.commit()
            return
        with self.engine.begin() as connection:
            if self.dialect_name == "postgresql":
                connection.exec_driver_sql("SELECT pg_advisory_xact_lock(742018311564702185)")
            _initialize_schema(connection)

    def close(self) -> None:
        self.engine.dispose()

    def schema_version(self) -> int:
        """Return the validated current schema version."""

        with self.engine.connect() as connection:
            _validate_current_schema(connection)
            version = connection.scalar(select(func.max(SchemaVersionRecord.version)))
            if version is None:
                raise SchemaInitializationError("cp_schema_version contains no migrations")
            return int(version)

    @staticmethod
    def next_event_sequence(session: Session, run_id: str) -> int:
        current = session.scalar(
            select(func.max(EventRecord.sequence)).where(EventRecord.run_id == run_id)
        )
        return int(current or 0) + 1

    @staticmethod
    def next_replay_event_sequence(session: Session, batch_id: str) -> int:
        current = session.scalar(
            select(func.max(ReplayEventRecord.sequence)).where(
                ReplayEventRecord.batch_id == batch_id
            )
        )
        return int(current or 0) + 1


_MIGRATIONS = {
    LEGACY_SCHEMA_VERSION: "legacy-control-plane-core",
    REPLAY_AUTHORITY_SCHEMA_VERSION: "replay-authority",
    ARTIFACT_AUTHORITY_SCHEMA_VERSION: "artifact-authority",
    CURRENT_SCHEMA_VERSION: "trusted-replay-compilation-authority",
}


def _initialize_schema(connection: Connection) -> None:
    inspector = inspect(connection)
    cp_tables = {
        table_name for table_name in inspector.get_table_names() if table_name.startswith("cp_")
    }
    if not cp_tables:
        _create_empty_schema(connection)
        _validate_current_schema(connection)
        return
    if cp_tables == LEGACY_CONTROL_PLANE_TABLES:
        _validate_tables(
            connection,
            LEGACY_CONTROL_PLANE_TABLES,
            allow_missing_v2_job_index=True,
        )
        _migrate_legacy_schema(connection)
        _validate_current_schema(connection)
        return
    if cp_tables == V2_CONTROL_PLANE_TABLES:
        _validate_v2_schema(connection)
        _migrate_v2_schema(connection)
        _validate_current_schema(connection)
        return
    if cp_tables == V3_CONTROL_PLANE_TABLES:
        _validate_v3_schema(connection)
        _migrate_v3_schema(connection)
        _validate_current_schema(connection)
        return
    if cp_tables == CURRENT_CONTROL_PLANE_TABLES:
        _validate_current_schema(connection)
        return

    unknown = sorted(cp_tables - CURRENT_CONTROL_PLANE_TABLES)
    missing = sorted(CURRENT_CONTROL_PLANE_TABLES - cp_tables)
    details: list[str] = []
    if unknown:
        details.append(f"unknown tables: {', '.join(unknown)}")
    if missing:
        details.append(f"missing tables: {', '.join(missing)}")
    raise SchemaInitializationError(
        "refusing partial or unknown Control Plane schema (" + "; ".join(details) + ")"
    )


def _create_empty_schema(connection: Connection) -> None:
    _create_tables(connection, LEGACY_CONTROL_PLANE_TABLES)
    _install_append_only_trigger(connection, "cp_events")
    Base.metadata.tables[SchemaVersionRecord.__tablename__].create(connection, checkfirst=False)
    _record_migration(connection, LEGACY_SCHEMA_VERSION)
    _record_migration(connection, REPLAY_AUTHORITY_SCHEMA_VERSION)
    _create_tables(connection, ARTIFACT_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_artifacts")
    _create_tables(connection, REPLAY_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_replay_events")
    _record_migration(connection, ARTIFACT_AUTHORITY_SCHEMA_VERSION)
    _create_tables(connection, REPLAY_COMPILATION_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_replay_compilations")
    _record_migration(connection, CURRENT_SCHEMA_VERSION)


def _migrate_legacy_schema(connection: Connection) -> None:
    _lock_legacy_migration_writes(connection)
    _assert_replay_authority_can_be_rebuilt(connection, schema_version=1)
    Base.metadata.tables[SchemaVersionRecord.__tablename__].create(connection, checkfirst=False)
    _record_migration(connection, LEGACY_SCHEMA_VERSION)
    _install_v2_job_binding_index(connection)
    _record_migration(connection, REPLAY_AUTHORITY_SCHEMA_VERSION)
    _create_tables(connection, ARTIFACT_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_artifacts")
    _create_tables(connection, REPLAY_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_replay_events")
    _record_migration(connection, ARTIFACT_AUTHORITY_SCHEMA_VERSION)
    _create_tables(connection, REPLAY_COMPILATION_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_replay_compilations")
    _record_migration(connection, CURRENT_SCHEMA_VERSION)


def _migrate_v2_schema(connection: Connection) -> None:
    _lock_v2_migration_writes(connection)
    _assert_replay_authority_can_be_rebuilt(connection, schema_version=2)

    _remove_append_only_trigger_support(connection, "cp_replay_events")
    for table_name in (
        "cp_replay_events",
        "cp_replay_tickets",
        "cp_replay_items",
        "cp_replay_batches",
    ):
        connection.exec_driver_sql(f"DROP TABLE {table_name}")
    _create_tables(connection, ARTIFACT_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_artifacts")
    _create_tables(connection, REPLAY_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_replay_events")
    _record_migration(connection, ARTIFACT_AUTHORITY_SCHEMA_VERSION)
    _create_tables(connection, REPLAY_COMPILATION_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_replay_compilations")
    _record_migration(connection, CURRENT_SCHEMA_VERSION)


def _assert_replay_authority_can_be_rebuilt(
    connection: Connection,
    *,
    schema_version: int,
) -> None:
    existing_tables = set(inspect(connection).get_table_names())
    nonempty_replay_tables = [
        table_name
        for table_name in sorted(REPLAY_AUTHORITY_TABLES)
        if table_name in existing_tables
        if connection.scalar(text(f"SELECT count(*) FROM {table_name}"))
    ]
    internal_replay_jobs = int(
        connection.scalar(text("SELECT count(*) FROM cp_jobs WHERE kind = 'internal-replay'")) or 0
    )
    if nonempty_replay_tables or internal_replay_jobs:
        details: list[str] = []
        if nonempty_replay_tables:
            details.append(f"nonempty Replay tables: {', '.join(nonempty_replay_tables)}")
        if internal_replay_jobs:
            details.append(f"internal-replay Jobs: {internal_replay_jobs}")
        raise SchemaInitializationError(
            f"schema v{schema_version} contains Replay authority without canonical "
            "compilations and cannot be trusted or backfilled (" + "; ".join(details) + ")"
        )


def _migrate_v3_schema(connection: Connection) -> None:
    _lock_v3_migration_writes(connection)
    _assert_replay_authority_can_be_rebuilt(connection, schema_version=3)

    _remove_append_only_trigger_support(connection, "cp_replay_events")
    for table_name in (
        "cp_replay_events",
        "cp_replay_tickets",
        "cp_replay_items",
        "cp_replay_batches",
    ):
        connection.exec_driver_sql(f"DROP TABLE {table_name}")
    _create_tables(connection, REPLAY_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_replay_events")
    _create_tables(connection, REPLAY_COMPILATION_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_replay_compilations")
    _record_migration(connection, CURRENT_SCHEMA_VERSION)


_LEGACY_MIGRATION_WRITE_LOCK_TABLES = ("cp_jobs",)
_V2_MIGRATION_WRITE_LOCK_TABLES = (
    "cp_jobs",
    "cp_replay_batches",
    "cp_replay_items",
    "cp_replay_tickets",
    "cp_replay_events",
)
_V3_MIGRATION_WRITE_LOCK_TABLES = _V2_MIGRATION_WRITE_LOCK_TABLES


def _lock_legacy_migration_writes(connection: Connection) -> None:
    """Exclude legacy Job writers while rejecting uncompiled Replay authority."""

    if connection.dialect.name == "sqlite":
        # ``initialize`` acquired BEGIN IMMEDIATE before inspecting the table set.
        return
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql("LOCK TABLE cp_jobs IN ACCESS EXCLUSIVE MODE")
        return
    raise SchemaInitializationError(
        f"unsupported Control Plane database dialect: {connection.dialect.name}"
    )


def _lock_v2_migration_writes(connection: Connection) -> None:
    """Exclude legacy writers from the v2 authority check through replacement."""

    if connection.dialect.name == "sqlite":
        # ``initialize`` acquired BEGIN IMMEDIATE before inspecting the table set.
        return
    if connection.dialect.name == "postgresql":
        tables = ", ".join(_V2_MIGRATION_WRITE_LOCK_TABLES)
        connection.exec_driver_sql(f"LOCK TABLE {tables} IN ACCESS EXCLUSIVE MODE")
        return
    raise SchemaInitializationError(
        f"unsupported Control Plane database dialect: {connection.dialect.name}"
    )


def _lock_v3_migration_writes(connection: Connection) -> None:
    """Exclude v3 writers from the canonical-compilation authority check."""

    if connection.dialect.name == "sqlite":
        # ``initialize`` acquired BEGIN IMMEDIATE before inspecting the table set.
        return
    if connection.dialect.name == "postgresql":
        tables = ", ".join(_V3_MIGRATION_WRITE_LOCK_TABLES)
        connection.exec_driver_sql(f"LOCK TABLE {tables} IN ACCESS EXCLUSIVE MODE")
        return
    raise SchemaInitializationError(
        f"unsupported Control Plane database dialect: {connection.dialect.name}"
    )


def _create_tables(connection: Connection, table_names: frozenset[str]) -> None:
    pending = set(table_names)
    for table in Base.metadata.sorted_tables:
        if table.name in pending:
            table.create(connection, checkfirst=False)
            pending.remove(table.name)
    if pending:
        raise SchemaInitializationError(
            f"migration metadata is missing tables: {', '.join(sorted(pending))}"
        )


def _install_v2_job_binding_index(connection: Connection) -> None:
    indexes = {index["name"] for index in inspect(connection).get_indexes("cp_jobs")}
    if "ux_cp_jobs_job_run" in indexes:
        return
    binding_index = next(
        index
        for index in Base.metadata.tables[JobRecord.__tablename__].indexes
        if index.name == "ux_cp_jobs_job_run"
    )
    binding_index.create(connection, checkfirst=False)


def _record_migration(connection: Connection, version: int) -> None:
    schema_version = Base.metadata.tables[SchemaVersionRecord.__tablename__]
    connection.execute(
        schema_version.insert().values(
            version=version,
            description=_MIGRATIONS[version],
            applied_at=utc_now(),
        )
    )


def _validate_current_schema(connection: Connection) -> None:
    inspector = inspect(connection)
    cp_tables = {
        table_name for table_name in inspector.get_table_names() if table_name.startswith("cp_")
    }
    if cp_tables != CURRENT_CONTROL_PLANE_TABLES:
        unknown = sorted(cp_tables - CURRENT_CONTROL_PLANE_TABLES)
        missing = sorted(CURRENT_CONTROL_PLANE_TABLES - cp_tables)
        raise SchemaInitializationError(
            "Control Plane schema table set does not match the current version "
            f"(unknown={unknown}, missing={missing})"
        )
    _validate_tables(connection, CURRENT_CONTROL_PLANE_TABLES)
    rows = connection.execute(
        select(
            SchemaVersionRecord.version,
            SchemaVersionRecord.description,
            SchemaVersionRecord.applied_at,
        ).order_by(SchemaVersionRecord.version)
    ).all()
    expected = [(version, _MIGRATIONS[version]) for version in sorted(_MIGRATIONS)]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema migration history: {actual!r}"
        )


def _validate_v2_schema(connection: Connection) -> None:
    _validate_tables(connection, V2_CONTROL_PLANE_TABLES, metadata=_V2_METADATA)
    rows = connection.execute(
        select(
            SchemaVersionRecord.version,
            SchemaVersionRecord.description,
            SchemaVersionRecord.applied_at,
        ).order_by(SchemaVersionRecord.version)
    ).all()
    expected = [
        (version, _MIGRATIONS[version])
        for version in (LEGACY_SCHEMA_VERSION, REPLAY_AUTHORITY_SCHEMA_VERSION)
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v2 migration history: {actual!r}"
        )


def _validate_v3_schema(connection: Connection) -> None:
    _validate_tables(connection, V3_CONTROL_PLANE_TABLES, metadata=_V3_METADATA)
    rows = connection.execute(
        select(
            SchemaVersionRecord.version,
            SchemaVersionRecord.description,
            SchemaVersionRecord.applied_at,
        ).order_by(SchemaVersionRecord.version)
    ).all()
    expected = [
        (version, _MIGRATIONS[version])
        for version in (
            LEGACY_SCHEMA_VERSION,
            REPLAY_AUTHORITY_SCHEMA_VERSION,
            ARTIFACT_AUTHORITY_SCHEMA_VERSION,
        )
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v3 migration history: {actual!r}"
        )


def _validate_tables(
    connection: Connection,
    table_names: frozenset[str],
    *,
    allow_missing_v2_job_index: bool = False,
    metadata: MetaData | None = None,
) -> None:
    inspector = inspect(connection)
    managed_metadata = metadata or Base.metadata
    for table_name in sorted(table_names):
        expected = managed_metadata.tables[table_name]
        actual_columns = {column["name"]: column for column in inspector.get_columns(table_name)}
        expected_columns = {column.name: column for column in expected.columns}
        if set(actual_columns) != set(expected_columns):
            raise SchemaInitializationError(
                f"{table_name} columns do not match managed schema "
                f"(actual={sorted(actual_columns)}, expected={sorted(expected_columns)})"
            )
        for name, column in expected_columns.items():
            actual = actual_columns[name]
            if bool(actual["nullable"]) != bool(column.nullable):
                raise SchemaInitializationError(
                    f"{table_name}.{name} nullability does not match managed schema"
                )
            if _column_type_family(actual["type"]) != _column_type_family(column.type):
                raise SchemaInitializationError(
                    f"{table_name}.{name} type does not match managed schema"
                )
            if (
                connection.dialect.name == "postgresql"
                and isinstance(column.type, DateTime)
                and bool(getattr(actual["type"], "timezone", False)) != bool(column.type.timezone)
            ):
                raise SchemaInitializationError(
                    f"{table_name}.{name} timezone does not match managed schema"
                )
            expected_length = getattr(column.type, "length", None)
            actual_length = getattr(actual["type"], "length", None)
            if expected_length is not None and actual_length != expected_length:
                raise SchemaInitializationError(
                    f"{table_name}.{name} length does not match managed schema"
                )

        actual_pk = tuple(inspector.get_pk_constraint(table_name).get("constrained_columns") or ())
        expected_pk = tuple(column.name for column in expected.primary_key.columns)
        if actual_pk != expected_pk:
            raise SchemaInitializationError(
                f"{table_name} primary key does not match managed schema"
            )
        _validate_unique_constraints(inspector, table_name, expected)
        _validate_foreign_keys(inspector, table_name, expected)
        _validate_check_constraints(connection, inspector, table_name, expected)
        if connection.dialect.name == "postgresql":
            _validate_postgres_constraint_flags(connection, table_name)
            _validate_postgres_relation_catalog(connection, table_name)
        _validate_indexes(
            inspector,
            table_name,
            expected,
            allow_missing_v2_job_index=allow_missing_v2_job_index,
        )
    _validate_trigger_inventory(connection, table_names)


def _column_type_family(column_type: Any) -> str:
    if isinstance(column_type, JSON):
        return "json"
    if isinstance(column_type, DateTime):
        return "datetime"
    if isinstance(column_type, Integer):
        return "integer"
    if isinstance(column_type, LargeBinary):
        return "binary"
    if isinstance(column_type, Text):
        return "text"
    if isinstance(column_type, String):
        return "string"
    return type(column_type).__name__.lower()


def _validate_unique_constraints(inspector: Any, table_name: str, expected: Any) -> None:
    from sqlalchemy import UniqueConstraint as SqlAlchemyUniqueConstraint

    expected_sets = Counter(
        tuple(column.name for column in constraint.columns)
        for constraint in expected.constraints
        if isinstance(constraint, SqlAlchemyUniqueConstraint)
    )
    inspected_constraints = inspector.get_unique_constraints(table_name)
    if any(
        bool((constraint.get("dialect_options") or {}).get("postgresql_nulls_not_distinct"))
        or bool(constraint.get("include_columns"))
        for constraint in inspected_constraints
    ):
        raise SchemaInitializationError(
            f"{table_name} has a unique constraint with unmanaged options"
        )
    actual_sets = Counter(
        tuple(constraint.get("column_names") or ()) for constraint in inspected_constraints
    )
    if expected_sets != actual_sets:
        raise SchemaInitializationError(
            f"{table_name} unique constraints do not match managed schema "
            f"(actual={sorted(actual_sets.elements())!r}, "
            f"expected={sorted(expected_sets.elements())!r})"
        )


def _validate_foreign_keys(inspector: Any, table_name: str, expected: Any) -> None:
    expected_fks = Counter(
        (
            tuple(element.parent.name for element in constraint.elements),
            str(constraint.referred_table.schema or ""),
            constraint.referred_table.name,
            tuple(element.column.name for element in constraint.elements),
            str(constraint.ondelete or "").upper(),
            str(constraint.onupdate or "").upper(),
            bool(constraint.deferrable),
            str(constraint.initially or "").upper(),
            str(constraint.match or "").upper(),
        )
        for constraint in expected.foreign_key_constraints
    )
    actual_fks = Counter(
        (
            tuple(constraint.get("constrained_columns") or ()),
            str(constraint.get("referred_schema") or ""),
            str(constraint.get("referred_table")),
            tuple(constraint.get("referred_columns") or ()),
            str((constraint.get("options") or {}).get("ondelete") or "").upper(),
            str((constraint.get("options") or {}).get("onupdate") or "").upper(),
            bool((constraint.get("options") or {}).get("deferrable")),
            str((constraint.get("options") or {}).get("initially") or "").upper(),
            str((constraint.get("options") or {}).get("match") or "").upper(),
        )
        for constraint in inspector.get_foreign_keys(table_name)
    )
    if expected_fks != actual_fks:
        raise SchemaInitializationError(f"{table_name} foreign keys do not match managed schema")


def _validate_check_constraints(
    connection: Connection, inspector: Any, table_name: str, expected: Any
) -> None:
    from sqlalchemy import CheckConstraint as SqlAlchemyCheckConstraint

    expected_constraints = {
        str(constraint.name): str(constraint.sqltext)
        for constraint in expected.constraints
        if isinstance(constraint, SqlAlchemyCheckConstraint)
    }
    inspected_constraints = inspector.get_check_constraints(table_name)
    if any(
        bool((constraint.get("dialect_options") or {}).get("postgresql_not_valid"))
        or bool((constraint.get("dialect_options") or {}).get("postgresql_no_inherit"))
        for constraint in inspected_constraints
    ):
        raise SchemaInitializationError(
            f"{table_name} has a check constraint with unmanaged options"
        )
    if any(constraint.get("name") is None for constraint in inspected_constraints):
        raise SchemaInitializationError(f"{table_name} has an unmanaged unnamed check constraint")
    actual_constraints = {
        str(constraint["name"]): str(constraint.get("sqltext") or "")
        for constraint in inspected_constraints
    }
    if len(actual_constraints) != len(inspected_constraints) or set(expected_constraints) != set(
        actual_constraints
    ):
        raise SchemaInitializationError(
            f"{table_name} check constraint set does not match managed schema "
            f"(actual={sorted(actual_constraints)!r}, "
            f"expected={sorted(expected_constraints)!r})"
        )
    for name, expected_sql in expected_constraints.items():
        actual_sql = actual_constraints[name]
        if connection.dialect.name == "sqlite":
            matches = _normalize_check_sql(actual_sql) == _normalize_check_sql(expected_sql)
        else:
            matches = _postgres_check_signature(actual_sql, expected_sql, expected)
        if not matches:
            raise SchemaInitializationError(
                f"{table_name} check constraint {name} does not match managed schema"
            )


def _validate_postgres_constraint_flags(connection: Connection, table_name: str) -> None:
    """Reject constraint states omitted by SQLAlchemy's PostgreSQL inspector."""

    rows = connection.execute(
        text(
            "SELECT managed_constraint.conname AS constraint_name, "
            "managed_constraint.contype AS constraint_type, "
            "managed_constraint.convalidated AS is_validated, "
            "managed_constraint.connoinherit AS no_inherit, "
            "managed_constraint.condeferrable AS is_deferrable, "
            "managed_constraint.condeferred AS is_initially_deferred "
            "FROM pg_constraint AS managed_constraint "
            "JOIN pg_class AS relation "
            "ON relation.oid = managed_constraint.conrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = current_schema() "
            "AND relation.relname = :table_name "
            "AND managed_constraint.contype IN ('c', 'f', 'u')"
        ),
        {"table_name": table_name},
    ).all()
    invalid = [
        str(row.constraint_name)
        for row in rows
        if not bool(row.is_validated)
        or (str(row.constraint_type) == "c" and bool(row.no_inherit))
        or bool(row.is_deferrable)
        or bool(row.is_initially_deferred)
    ]
    if invalid:
        raise SchemaInitializationError(
            f"{table_name} has constraints with unmanaged catalog flags: {sorted(invalid)!r}"
        )


def _validate_postgres_relation_catalog(connection: Connection, table_name: str) -> None:
    """Validate PostgreSQL relation properties and semantic hook inventory."""

    relation_rows = connection.execute(
        text(
            "SELECT relation.relkind AS relation_kind, "
            "relation.relpersistence AS relation_persistence, "
            "EXISTS ("
            "SELECT 1 FROM pg_inherits AS inheritance "
            "WHERE inheritance.inhparent = relation.oid "
            "OR inheritance.inhrelid = relation.oid"
            ") AS has_inheritance "
            "FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = current_schema() "
            "AND relation.relname = :table_name"
        ),
        {"table_name": table_name},
    ).all()
    if len(relation_rows) != 1:
        raise SchemaInitializationError(
            f"{table_name} relation catalog does not match managed schema"
        )
    relation = relation_rows[0]
    if str(relation.relation_kind) != "r":
        raise SchemaInitializationError(f"{table_name} relation kind does not match managed schema")
    if str(relation.relation_persistence) != "p":
        raise SchemaInitializationError(
            f"{table_name} relation persistence does not match managed schema"
        )
    if bool(relation.has_inheritance):
        raise SchemaInitializationError(
            f"{table_name} inheritance inventory does not match managed schema"
        )

    rows = connection.execute(
        text(
            "SELECT rewrite.rulename AS rule_name "
            "FROM pg_rewrite AS rewrite "
            "JOIN pg_class AS relation ON relation.oid = rewrite.ev_class "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = current_schema() "
            "AND relation.relname = :table_name"
        ),
        {"table_name": table_name},
    ).all()
    if rows:
        raise SchemaInitializationError(
            f"{table_name} rewrite rule inventory does not match managed schema: "
            f"{sorted(str(row.rule_name) for row in rows)!r}"
        )


def _normalize_check_sql(value: str) -> str:
    normalized = re.sub(r"\s+", "", value.lower().replace('"', "").replace("`", ""))
    while normalized.startswith("(") and normalized.endswith(")"):
        depth = 0
        encloses_all = True
        for index, character in enumerate(normalized):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0 and index != len(normalized) - 1:
                    encloses_all = False
                    break
        if not encloses_all:
            break
        normalized = normalized[1:-1]
    return normalized


def _postgres_check_signature(actual_sql: str, expected_sql: str, table: Any) -> bool:
    """Compare repository-owned CHECK structure, tolerating only PostgreSQL rendering.

    PostgreSQL renders ``IN`` as ``= ANY (ARRAY[...])`` and adds casts and
    parentheses.  Token-count signatures cannot distinguish operand or range
    reordering, so both forms are parsed into a small AST covering every CHECK
    expression declared by this module.  Unknown syntax fails closed.
    """

    allowed_columns = frozenset(column.name.lower() for column in table.columns)
    textual_columns = frozenset(
        column.name.lower() for column in table.columns if isinstance(column.type, (String, Text))
    )
    try:
        actual = _PostgresCheckParser(actual_sql, allowed_columns, textual_columns).parse()
        expected = _PostgresCheckParser(expected_sql, allowed_columns, textual_columns).parse()
    except ValueError:
        return False
    return actual == expected


_CHECK_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<string>'(?:''|[^'])*')|"
    r'(?P<quoted>"(?:""|[^"])*")|'
    r"(?P<number>\d+)|"
    r"(?P<arithmetic>[+-])|"
    r"(?P<cast>::)|"
    r"(?P<operator><>|!=|>=|<=|=|>|<)|"
    r"(?P<punct>[(),\[\]])|"
    r"(?P<word>[a-z_][a-z0-9_]*)"
    r")",
    re.IGNORECASE,
)


def _tokenize_postgres_check(value: str) -> list[tuple[str, str]]:
    stripped = value.strip()
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(stripped):
        match = _CHECK_TOKEN_RE.match(stripped, position)
        if match is None:
            raise ValueError("unsupported PostgreSQL CHECK syntax")
        kind = str(match.lastgroup)
        token = match.group(kind)
        if kind == "string":
            token = token[1:-1].replace("''", "'")
        elif kind == "quoted":
            kind = "word"
            token = token[1:-1].replace('""', '"').lower()
        elif kind == "word":
            token = token.lower()
        tokens.append((kind, token))
        position = match.end()
    return tokens


class _PostgresCheckParser:
    """Parser for the deliberately small CHECK grammar owned by this schema."""

    def __init__(
        self,
        value: str,
        allowed_columns: frozenset[str],
        textual_columns: frozenset[str],
    ) -> None:
        self._tokens = _tokenize_postgres_check(value)
        self._position = 0
        self._allowed_columns = allowed_columns
        self._textual_columns = textual_columns

    def parse(self) -> tuple[Any, ...]:
        if self._accept_word("check"):
            self._expect_punct("(")
            result = self._parse_or()
            self._expect_punct(")")
        else:
            result = self._parse_or()
        if self._position != len(self._tokens):
            raise ValueError("trailing PostgreSQL CHECK syntax")
        return result

    def _parse_or(self) -> tuple[Any, ...]:
        parts = [self._parse_and()]
        while self._accept_word("or"):
            parts.append(self._parse_and())
        return parts[0] if len(parts) == 1 else ("or", *parts)

    def _parse_and(self) -> tuple[Any, ...]:
        parts = [self._parse_predicate()]
        while self._accept_word("and"):
            parts.append(self._parse_predicate())
        return parts[0] if len(parts) == 1 else ("and", *parts)

    def _parse_predicate(self) -> tuple[Any, ...]:
        if self._peek() == ("punct", "(") and not self._leading_parenthesis_is_operand():
            self._position += 1
            expression = self._parse_or()
            self._expect_punct(")")
            return expression

        left = self._parse_operand()
        if self._accept_word("is"):
            negated = self._accept_word("not")
            self._expect_word("null")
            return ("is-null", left, negated)

        negated = self._accept_word("not")
        if self._accept_word("in"):
            values = self._parse_parenthesized_values(array=False)
            return ("in", left, values, negated)
        if negated:
            raise ValueError("NOT must qualify IN or NULL")

        operator = self._expect_kind("operator")
        if operator == "=" and self._accept_word("any"):
            values = self._parse_parenthesized_values(array=True)
            return ("in", left, values, False)
        right = self._parse_operand()
        return ("compare", operator, left, right)

    def _parse_operand(self) -> tuple[Any, ...]:
        value = self._parse_primary()
        while (token := self._peek()) is not None and token[0] == "arithmetic":
            operator = self._expect_kind("arithmetic")
            value = ("arithmetic", operator, value, self._parse_primary())
        return value

    def _parse_primary(self) -> tuple[Any, ...]:
        if self._accept_punct("("):
            value = self._parse_operand()
            self._expect_punct(")")
        else:
            token = self._peek()
            if token is None:
                raise ValueError("missing CHECK operand")
            kind, token_value = token
            if kind == "number":
                self._position += 1
                value = ("number", int(token_value))
            elif kind == "string":
                self._position += 1
                value = ("string", token_value)
            elif kind != "word":
                raise ValueError("unsupported CHECK operand")
            else:
                self._position += 1
                if self._accept_punct("("):
                    if token_value == "length":
                        arguments = [self._parse_operand()]
                    elif token_value in {"replace", "substr"}:
                        arguments = [self._parse_operand()]
                        self._expect_punct(",")
                        arguments.append(self._parse_operand())
                        self._expect_punct(",")
                        arguments.append(self._parse_operand())
                    else:
                        raise ValueError("unsupported CHECK function")
                    self._expect_punct(")")
                    value = ("function", token_value, *arguments)
                else:
                    if token_value not in self._allowed_columns:
                        raise ValueError("CHECK references an unmanaged identifier")
                    value = ("column", token_value)
        return self._consume_text_casts(value, array=False)

    def _parse_parenthesized_values(self, *, array: bool) -> tuple[tuple[Any, ...], ...]:
        self._expect_punct("(")
        nested = self._accept_punct("(")
        if array:
            self._expect_word("array")
            self._expect_punct("[")
            closing = "]"
        else:
            closing = ")"
        values = [self._parse_operand()]
        while self._accept_punct(","):
            values.append(self._parse_operand())
        self._expect_punct(closing)
        if nested:
            self._expect_punct(")")
        self._consume_text_casts(("array",), array=True)
        if array:
            self._expect_punct(")")
        if any(value[0] not in {"string", "number"} for value in values):
            raise ValueError("unsupported CHECK membership value")
        return tuple(values)

    def _leading_parenthesis_is_operand(self) -> bool:
        depth = 0
        for position in range(self._position, len(self._tokens)):
            token = self._tokens[position]
            if token == ("punct", "("):
                depth += 1
            elif token == ("punct", ")"):
                depth -= 1
                if depth == 0:
                    following = (
                        self._tokens[position + 1] if position + 1 < len(self._tokens) else None
                    )
                    return following is not None and (
                        following[0] in {"operator", "cast", "arithmetic"}
                        or following
                        in {
                            ("word", "is"),
                            ("word", "in"),
                            ("word", "not"),
                        }
                    )
        raise ValueError("unbalanced PostgreSQL CHECK parentheses")

    def _consume_text_casts(self, value: tuple[Any, ...], *, array: bool) -> tuple[Any, ...]:
        while self._peek() == ("cast", "::"):
            self._position += 1
            cast_name = self._expect_kind("word")
            if cast_name == "character":
                self._expect_word("varying")
            elif cast_name not in {"text", "varchar"}:
                raise ValueError("unsupported PostgreSQL CHECK cast")
            has_array_suffix = self._accept_punct("[")
            if has_array_suffix:
                self._expect_punct("]")
            if has_array_suffix != array:
                raise ValueError("CHECK cast shape does not match its operand")
            if not array and not (
                value[0] == "string"
                or (value[0] == "column" and value[1] in self._textual_columns)
                or (value[0] == "function" and value[1] in {"replace", "substr"})
            ):
                raise ValueError("text cast is not a PostgreSQL rendering cast")
        return value

    def _peek(self) -> tuple[str, str] | None:
        if self._position == len(self._tokens):
            return None
        return self._tokens[self._position]

    def _accept_word(self, value: str) -> bool:
        if self._peek() == ("word", value):
            self._position += 1
            return True
        return False

    def _expect_word(self, value: str) -> None:
        if not self._accept_word(value):
            raise ValueError(f"expected CHECK keyword {value}")

    def _accept_punct(self, value: str) -> bool:
        if self._peek() == ("punct", value):
            self._position += 1
            return True
        return False

    def _expect_punct(self, value: str) -> None:
        if not self._accept_punct(value):
            raise ValueError(f"expected CHECK punctuation {value}")

    def _expect_kind(self, kind: str) -> str:
        token = self._peek()
        if token is None or token[0] != kind:
            raise ValueError(f"expected CHECK token kind {kind}")
        self._position += 1
        return token[1]


def _validate_indexes(
    inspector: Any,
    table_name: str,
    expected: Any,
    *,
    allow_missing_v2_job_index: bool,
) -> None:
    expected_indexes = {
        (index.name, tuple(column.name for column in index.columns), bool(index.unique))
        for index in expected.indexes
    }
    if allow_missing_v2_job_index and table_name == "cp_jobs":
        expected_indexes = {index for index in expected_indexes if index[0] != "ux_cp_jobs_job_run"}
    inspected_indexes = [
        index
        for index in inspector.get_indexes(table_name)
        if not index.get("duplicates_constraint")
    ]
    for index in inspected_indexes:
        dialect_options = index.get("dialect_options") or {}
        if (
            any(column is None for column in (index.get("column_names") or ()))
            or bool(index.get("column_sorting"))
            or bool(index.get("include_columns"))
            or dialect_options.get("postgresql_where") is not None
            or bool(dialect_options.get("postgresql_include"))
        ):
            raise SchemaInitializationError(
                f"{table_name} index {index.get('name')!r} has unmanaged options"
            )
    actual_indexes = {
        (
            index.get("name"),
            tuple(index.get("column_names") or ()),
            bool(index.get("unique")),
        )
        for index in inspected_indexes
    }
    if expected_indexes != actual_indexes:
        raise SchemaInitializationError(
            f"{table_name} indexes do not match managed schema "
            f"(actual={sorted(actual_indexes)!r}, expected={sorted(expected_indexes)!r})"
        )


_APPEND_ONLY_TABLE_SUFFIXES = {
    "cp_events": "event",
    "cp_artifacts": "artifact",
    "cp_replay_compilations": "replay_compilation",
    "cp_replay_events": "replay_event",
}


def _install_append_only_trigger(connection: Connection, table_name: str) -> None:
    if table_name not in _APPEND_ONLY_TABLE_SUFFIXES:
        raise ValueError(f"unsupported append-only table: {table_name}")
    if connection.dialect.name == "postgresql":
        suffix = _APPEND_ONLY_TABLE_SUFFIXES[table_name]
        function_name = f"pajin_cp_reject_{suffix}_mutation"
        trigger_name = f"{table_name}_append_only"
        connection.exec_driver_sql(
            f"""
            CREATE FUNCTION {function_name}()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              RAISE EXCEPTION '{table_name} is append-only';
            END;
            $$
            """
        )
        connection.exec_driver_sql(
            f"""
            CREATE TRIGGER {trigger_name}
            BEFORE UPDATE OR DELETE ON {table_name}
            FOR EACH ROW EXECUTE FUNCTION {function_name}()
            """
        )
    elif connection.dialect.name == "sqlite":
        for operation in ("UPDATE", "DELETE"):
            trigger_name = f"{table_name}_no_{operation.lower()}"
            connection.exec_driver_sql(
                f"""
                CREATE TRIGGER {trigger_name}
                BEFORE {operation} ON {table_name}
                BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END
                """
            )
    else:
        raise SchemaInitializationError(
            f"unsupported Control Plane database dialect: {connection.dialect.name}"
        )


def _remove_append_only_trigger_support(connection: Connection, table_name: str) -> None:
    if table_name not in _APPEND_ONLY_TABLE_SUFFIXES:
        raise ValueError(f"unsupported append-only table: {table_name}")
    if connection.dialect.name == "sqlite":
        for operation in ("UPDATE", "DELETE"):
            connection.exec_driver_sql(f"DROP TRIGGER {table_name}_no_{operation.lower()}")
        return
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(f"DROP TRIGGER {table_name}_append_only ON {table_name}")
        suffix = _APPEND_ONLY_TABLE_SUFFIXES[table_name]
        connection.exec_driver_sql(f"DROP FUNCTION pajin_cp_reject_{suffix}_mutation()")
        return
    raise SchemaInitializationError(
        f"unsupported Control Plane database dialect: {connection.dialect.name}"
    )


def _validate_trigger_inventory(connection: Connection, table_names: frozenset[str]) -> None:
    for table_name in sorted(table_names):
        if table_name in _APPEND_ONLY_TABLE_SUFFIXES:
            _validate_append_only_trigger(connection, table_name)
        else:
            _validate_no_user_triggers(connection, table_name)


def _validate_no_user_triggers(connection: Connection, table_name: str) -> None:
    if connection.dialect.name == "sqlite":
        names = connection.scalars(
            text(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = :table_name"
            ),
            {"table_name": table_name},
        ).all()
    elif connection.dialect.name == "postgresql":
        names = connection.scalars(
            text(
                "SELECT trigger.tgname "
                "FROM pg_trigger AS trigger "
                "JOIN pg_class AS relation ON relation.oid = trigger.tgrelid "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = current_schema() "
                "AND relation.relname = :table_name AND NOT trigger.tgisinternal"
            ),
            {"table_name": table_name},
        ).all()
    else:
        raise SchemaInitializationError(
            f"unsupported Control Plane database dialect: {connection.dialect.name}"
        )
    if names:
        raise SchemaInitializationError(
            f"{table_name} user trigger inventory does not match managed schema: "
            f"{sorted(str(name) for name in names)!r}"
        )


def _validate_append_only_trigger(connection: Connection, table_name: str) -> None:
    if connection.dialect.name == "sqlite":
        rows = connection.execute(
            text(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type = 'trigger' AND tbl_name = :table_name"
            ),
            {"table_name": table_name},
        ).all()
        definitions = {str(row.name): str(row.sql or "").upper() for row in rows}
        expected_names: set[str] = set()
        for operation in ("UPDATE", "DELETE"):
            name = f"{table_name}_no_{operation.lower()}"
            expected_names.add(name)
            definition = definitions.get(name, "")
            expected_definition = f"""
                CREATE TRIGGER {name}
                BEFORE {operation} ON {table_name}
                BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END
            """
            if _normalize_trigger_sql(definition) != _normalize_trigger_sql(expected_definition):
                raise SchemaInitializationError(
                    f"{table_name} append-only {operation.lower()} trigger is missing or invalid"
                )
        if set(definitions) != expected_names:
            raise SchemaInitializationError(
                f"{table_name} user trigger inventory does not match managed schema: "
                f"{sorted(definitions)!r}"
            )
        return
    if connection.dialect.name == "postgresql":
        rows = connection.execute(
            text(
                "SELECT trigger.tgname AS trigger_name, "
                "trigger.tgenabled AS trigger_enabled, "
                "trigger.tgtype AS trigger_type, "
                "trigger.tgattr = ''::int2vector AS no_trigger_columns, "
                "trigger.tgqual IS NOT NULL AS has_when, "
                "octet_length(trigger.tgargs) AS trigger_arguments_length, "
                "procedure.proname AS function_name, "
                "function_namespace.nspname AS function_schema, "
                "current_schema() AS expected_schema, "
                "language.lanname AS function_language, "
                "procedure.pronargs AS function_argument_count, "
                "procedure.prorettype = 'trigger'::regtype AS returns_trigger, "
                "procedure.prokind AS function_kind, "
                "procedure.prosecdef AS security_definer, "
                "procedure.proleakproof AS leakproof, "
                "procedure.provolatile AS volatility, "
                "procedure.proparallel AS parallel_mode, "
                "procedure.proconfig IS NULL AS no_function_config, "
                "procedure.prosrc AS function_source "
                "FROM pg_trigger AS trigger "
                "JOIN pg_class AS relation ON relation.oid = trigger.tgrelid "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_proc AS procedure ON procedure.oid = trigger.tgfoid "
                "JOIN pg_namespace AS function_namespace "
                "ON function_namespace.oid = procedure.pronamespace "
                "JOIN pg_language AS language ON language.oid = procedure.prolang "
                "WHERE namespace.nspname = current_schema() "
                "AND relation.relname = :table_name AND NOT trigger.tgisinternal"
            ),
            {"table_name": table_name},
        ).all()
        trigger_name = f"{table_name}_append_only"
        matching = [row for row in rows if row.trigger_name == trigger_name]
        if len(matching) != 1:
            raise SchemaInitializationError(
                f"{table_name} append-only trigger is missing or invalid"
            )
        if len(rows) != 1:
            raise SchemaInitializationError(
                f"{table_name} user trigger inventory does not match managed schema: "
                f"{sorted(str(row.trigger_name) for row in rows)!r}"
            )
        if not _postgres_append_only_trigger_is_valid(matching[0], table_name):
            raise SchemaInitializationError(
                f"{table_name} append-only trigger is missing or invalid"
            )
        return
    raise SchemaInitializationError(
        f"unsupported Control Plane database dialect: {connection.dialect.name}"
    )


def _postgres_append_only_trigger_is_valid(row: Any, table_name: str) -> bool:
    suffix = _APPEND_ONLY_TABLE_SUFFIXES.get(table_name)
    if suffix is None:
        return False
    expected_function_source = f"""
        BEGIN
          RAISE EXCEPTION '{table_name} is append-only';
        END;
    """
    # PostgreSQL tgtype bitmask: ROW | BEFORE | DELETE | UPDATE.
    expected_trigger_type = 1 | 2 | 8 | 16
    return (
        str(row.trigger_enabled) == "O"
        and int(row.trigger_type) == expected_trigger_type
        and bool(row.no_trigger_columns)
        and not bool(row.has_when)
        and int(row.trigger_arguments_length) == 0
        and str(row.function_name) == f"pajin_cp_reject_{suffix}_mutation"
        and str(row.function_schema) == str(row.expected_schema)
        and str(row.function_language) == "plpgsql"
        and int(row.function_argument_count) == 0
        and bool(row.returns_trigger)
        and str(row.function_kind) == "f"
        and not bool(row.security_definer)
        and not bool(row.leakproof)
        and str(row.volatility) == "v"
        and str(row.parallel_mode) == "u"
        and bool(row.no_function_config)
        and _normalize_trigger_sql(str(row.function_source))
        == _normalize_trigger_sql(expected_function_source)
    )


def _normalize_trigger_sql(value: str) -> str:
    return re.sub(r"\s+", "", value).rstrip(";").lower()


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()
