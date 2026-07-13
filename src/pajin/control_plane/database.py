"""SQLAlchemy schema and transaction boundary for the durable Control Plane."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    func,
    select,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


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
    __table_args__ = (Index("ix_cp_jobs_claim", "state", "available_at", "priority", "created_at"),)

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
        Base.metadata.create_all(self.engine)
        self._install_append_only_guard(self.engine)

    def close(self) -> None:
        self.engine.dispose()

    @staticmethod
    def next_event_sequence(session: Session, run_id: str) -> int:
        current = session.scalar(
            select(func.max(EventRecord.sequence)).where(EventRecord.run_id == run_id)
        )
        return int(current or 0) + 1

    @staticmethod
    def _install_append_only_guard(engine: Engine) -> None:
        with engine.begin() as connection:
            if engine.dialect.name == "postgresql":
                connection.exec_driver_sql(
                    """
                    CREATE OR REPLACE FUNCTION pajin_cp_reject_event_mutation()
                    RETURNS trigger LANGUAGE plpgsql AS $$
                    BEGIN
                      RAISE EXCEPTION 'cp_events is append-only';
                    END;
                    $$
                    """
                )
                connection.exec_driver_sql(
                    """
                    DROP TRIGGER IF EXISTS cp_events_append_only ON cp_events
                    """
                )
                connection.exec_driver_sql(
                    """
                    CREATE TRIGGER cp_events_append_only
                    BEFORE UPDATE OR DELETE ON cp_events
                    FOR EACH ROW EXECUTE FUNCTION pajin_cp_reject_event_mutation()
                    """
                )
            elif engine.dialect.name == "sqlite":
                connection.exec_driver_sql(
                    """
                    CREATE TRIGGER IF NOT EXISTS cp_events_no_update
                    BEFORE UPDATE ON cp_events
                    BEGIN SELECT RAISE(ABORT, 'cp_events is append-only'); END
                    """
                )
                connection.exec_driver_sql(
                    """
                    CREATE TRIGGER IF NOT EXISTS cp_events_no_delete
                    BEFORE DELETE ON cp_events
                    BEGIN SELECT RAISE(ABORT, 'cp_events is append-only'); END
                    """
                )


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()
