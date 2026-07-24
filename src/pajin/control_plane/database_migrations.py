"""Forward-only migration transactions, writer locks, and DDL installation."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import (
    JSON,
    DateTime,
    MetaData,
    Table,
    Text,
    inspect,
    select,
    text,
)
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from pajin.control_plane.database_dialect import (
    _APPEND_ONLY_TABLE_SUFFIXES,
    _LEASE_AUTHORITY_FUNCTION_NAME,
    _LEASE_AUTHORITY_TRIGGER_NAME,
    _SUBMISSION_AUTHORITY_FUNCTION_NAME,
    _SUBMISSION_AUTHORITY_TRIGGER_NAME,
    _column_type_family,
    _is_managed_postgres_sequence_default,
    _lease_authority_is_invalid_sql,
    _postgres_lease_authority_function_source,
    _postgres_submission_authority_function_source,
    _run_authority_is_valid_sql,
    _sqlite_authority_delete_trigger_sql,
    _sqlite_authority_rowid_trigger_sql,
    _sqlite_lease_authority_trigger_sql,
    _sqlite_no_replace_trigger_sql,
    _sqlite_submission_authority_trigger_sql,
    _strict_json_object,
    _validate_check_constraints,
    _validate_foreign_keys,
    _validate_indexes,
    _validate_postgres_constraint_flags,
    _validate_postgres_relation_catalog,
    _validate_sqlite_datetime_columns,
    _validate_trigger_inventory,
    _validate_unique_constraints,
)
from pajin.control_plane.database_dialect import (
    _json_object_is_valid_sql as _json_object_is_valid_sql,
)
from pajin.control_plane.database_dialect import (
    _postgres_append_only_trigger_is_valid as _postgres_append_only_trigger_is_valid,
)
from pajin.control_plane.database_dialect import (
    _postgres_check_signature as _postgres_check_signature,
)
from pajin.control_plane.database_dialect import (
    _postgres_truncate_trigger_is_valid as _postgres_truncate_trigger_is_valid,
)
from pajin.control_plane.database_dialect import (
    _validate_append_only_trigger as _validate_append_only_trigger,
)
from pajin.control_plane.database_schema import (
    _JOB_JSON_STORAGE_MAX_BYTES,
    _JSON_AUTHORITY_BATCH_SIZE,
    _MIGRATION_BACKFILL_BATCH_SIZE,
    _RUN_JSON_STORAGE_MAX_BYTES,
    _SQLITE_BUSY_TIMEOUT_MILLISECONDS,
    _V2_METADATA,
    _V3_METADATA,
    _V4_METADATA,
    _V5_METADATA,
    _V6_METADATA,
    _V7_METADATA,
    _V9_METADATA,
    _V10_METADATA,
    _V11_METADATA,
    _V12_METADATA,
    _V13_METADATA,
    ARTIFACT_AUTHORITY_SCHEMA_VERSION,
    ARTIFACT_AUTHORITY_TABLES,
    COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
    CURRENT_CONTROL_PLANE_TABLES,
    CURRENT_SCHEMA_VERSION,
    DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION,
    LEGACY_CONTROL_PLANE_TABLES,
    LEGACY_SCHEMA_VERSION,
    REPLAY_AUTHORITY_SCHEMA_VERSION,
    REPLAY_AUTHORITY_TABLES,
    REPLAY_CLAIM_PROJECTION_AUTHORITY_TABLES,
    REPLAY_CLAIM_PROJECTION_SCHEMA_VERSION,
    REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION,
    REPLAY_COMPILATION_AUTHORITY_TABLES,
    REPLAY_EXECUTION_CONTEXT_AUTHORITY_TABLES,
    REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION,
    REPLAY_FINALIZATION_AUTHORITY_TABLES,
    REPLAY_FINALIZATION_SCHEMA_VERSION,
    REPLAY_PROJECTION_AUTHORITY_SCHEMA_VERSION,
    REPLAY_PROJECTION_AUTHORITY_TABLES,
    REPLAY_RETEST_SOURCE_AUTHORITY_SCHEMA_VERSION,
    REPLAY_RETEST_SOURCE_AUTHORITY_TABLES,
    REPLAY_TOOL_PERMIT_AUTHORITY_TABLES,
    REPLAY_TOOL_PERMIT_SCHEMA_VERSION,
    SUBMISSION_AND_LEASE_AUTHORITY_SCHEMA_VERSION,
    TARGET_ATTESTATION_REGISTRY_AUTHORITY_TABLES,
    TARGET_ATTESTATION_REGISTRY_SCHEMA_VERSION,
    V2_CONTROL_PLANE_TABLES,
    V3_CONTROL_PLANE_TABLES,
    V4_CONTROL_PLANE_TABLES,
    V5_CONTROL_PLANE_TABLES,
    V6_CONTROL_PLANE_TABLES,
    V7_CONTROL_PLANE_TABLES,
    V8_CONTROL_PLANE_TABLES,
    V10_CONTROL_PLANE_TABLES,
    V11_CONTROL_PLANE_TABLES,
    V12_CONTROL_PLANE_TABLES,
    V13_CONTROL_PLANE_TABLES,
    Base,
    EventRecord,
    JobRecord,
    ReplayBatchRecord,
    ReplayBudgetAccountRecord,
    ReplayBudgetReservationRecord,
    ReplayClaimBindingRecord,
    ReplayCompilationRecord,
    ReplayEventRecord,
    ReplayExecutionContextRecord,
    ReplayFinalizationRecord,
    ReplayItemRecord,
    ReplayProjectionRecord,
    ReplayRateAccountRecord,
    ReplayRateReservationRecord,
    ReplayRetestSourceRecord,
    ReplayTicketRecord,
    ReplayToolPermitRecord,
    RunRecord,
    SchemaInitializationError,
    SchemaVersionRecord,
    TargetAttestationRegistryVersionRecord,
    _replay_ticket_permit_authority_index,
)
from pajin.control_plane.models import (
    CONTROL_PLANE_STORED_JSON_POLICY,
    SUBMIT_RUN_INPUT_JSON_POLICY,
    job_submission_authority_digest,
    non_replayable_submission_authority_digest,
    submission_authority_digest,
    validate_bounded_json_object,
)


def utc_now() -> datetime:
    """Return one timezone-aware timestamp for migration authority rows."""

    return datetime.now(UTC)


_MIGRATIONS = {
    LEGACY_SCHEMA_VERSION: "legacy-control-plane-core",
    REPLAY_AUTHORITY_SCHEMA_VERSION: "replay-authority",
    ARTIFACT_AUTHORITY_SCHEMA_VERSION: "artifact-authority",
    REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION: "trusted-replay-compilation-authority",
    DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION: "durable-replay-permit-authority",
    REPLAY_TOOL_PERMIT_SCHEMA_VERSION: "replay-tool-call-permit-authority",
    REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION: "replay-execution-context-authority",
    COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION: "complete-append-only-guards",
    REPLAY_FINALIZATION_SCHEMA_VERSION: "server-derived-replay-finalization",
    SUBMISSION_AND_LEASE_AUTHORITY_SCHEMA_VERSION: "submission-and-lease-authority",
    REPLAY_PROJECTION_AUTHORITY_SCHEMA_VERSION: "versioned-replay-projection-authority",
    REPLAY_RETEST_SOURCE_AUTHORITY_SCHEMA_VERSION: "negative-retest-source-authority",
    REPLAY_CLAIM_PROJECTION_SCHEMA_VERSION: "claim-specific-replay-projection-authority",
    TARGET_ATTESTATION_REGISTRY_SCHEMA_VERSION: (
        "signed-target-attestation-registry-anti-rollback-authority"
    ),
}


def _initialize_schema(connection: Connection) -> None:  # noqa: C901
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
            metadata=_V9_METADATA,
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
    if cp_tables == V4_CONTROL_PLANE_TABLES:
        _validate_v4_schema(connection)
        _migrate_v4_schema(connection)
        _validate_current_schema(connection)
        return
    if cp_tables == V5_CONTROL_PLANE_TABLES:
        _validate_v5_schema(connection)
        _migrate_v5_schema(connection)
        _validate_current_schema(connection)
        return
    if cp_tables == V6_CONTROL_PLANE_TABLES:
        _validate_v6_schema(connection)
        _migrate_v6_schema(connection)
        _validate_current_schema(connection)
        return
    if cp_tables == V8_CONTROL_PLANE_TABLES:
        latest = _latest_schema_version(connection)
        if latest == REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION:
            _validate_v7_schema(connection)
            _migrate_v7_schema(connection)
        elif latest == COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION:
            _validate_v8_schema(connection)
        else:
            raise SchemaInitializationError(
                f"unknown migration history for schema-v8 table set: {latest!r}"
            )
        _migrate_v8_schema(connection)
        _validate_current_schema(connection)
        return
    if cp_tables == V10_CONTROL_PLANE_TABLES:
        _initialize_v10_table_set(connection)
        return
    if cp_tables == V11_CONTROL_PLANE_TABLES:
        if _latest_schema_version(connection) != REPLAY_PROJECTION_AUTHORITY_SCHEMA_VERSION:
            raise SchemaInitializationError("unknown migration history for schema-v11 table set")
        _validate_v11_schema(connection)
        _migrate_v11_schema(connection)
        _validate_current_schema(connection)
        return
    if cp_tables == V12_CONTROL_PLANE_TABLES:
        if _latest_schema_version(connection) != REPLAY_RETEST_SOURCE_AUTHORITY_SCHEMA_VERSION:
            raise SchemaInitializationError("unknown migration history for schema-v12 table set")
        _validate_v12_schema(connection)
        _migrate_v12_schema(connection)
        _validate_current_schema(connection)
        return
    if cp_tables == V13_CONTROL_PLANE_TABLES:
        if _latest_schema_version(connection) != REPLAY_CLAIM_PROJECTION_SCHEMA_VERSION:
            raise SchemaInitializationError("unknown migration history for schema-v13 table set")
        _validate_v13_schema(connection)
        _migrate_v13_schema(connection)
        _validate_current_schema(connection)
        return
    if cp_tables == CURRENT_CONTROL_PLANE_TABLES:
        latest = _latest_schema_version(connection)
        if latest != CURRENT_SCHEMA_VERSION:
            raise SchemaInitializationError(
                "unknown migration history for current Control Plane table set"
            )
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


def _initialize_v10_table_set(connection: Connection) -> None:
    """Validate and advance either v9 or v10 from their shared table set."""

    latest = _latest_schema_version(connection)
    if latest == REPLAY_FINALIZATION_SCHEMA_VERSION:
        _validate_v9_schema(connection)
        _migrate_v9_schema(connection)
        _validate_current_schema(connection)
        return
    if latest == SUBMISSION_AND_LEASE_AUTHORITY_SCHEMA_VERSION:
        _validate_v10_schema(connection)
        _migrate_v10_schema(connection)
        _validate_current_schema(connection)
        return
    raise SchemaInitializationError(
        f"unknown migration history for schema-v10 table set: {latest!r}"
    )


def _create_empty_schema(connection: Connection) -> None:
    _create_tables(connection, LEGACY_CONTROL_PLANE_TABLES)
    _install_append_only_trigger(connection, "cp_events")
    Base.metadata.tables[SchemaVersionRecord.__tablename__].create(connection, checkfirst=False)
    _record_migration(connection, LEGACY_SCHEMA_VERSION)
    _record_migration(connection, REPLAY_AUTHORITY_SCHEMA_VERSION)
    _create_tables(connection, ARTIFACT_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_artifacts")
    _record_migration(connection, ARTIFACT_AUTHORITY_SCHEMA_VERSION)
    _create_current_replay_authority(connection)
    _record_migration(connection, REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION)
    _record_migration(connection, DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION)
    _record_migration(connection, REPLAY_TOOL_PERMIT_SCHEMA_VERSION)
    _record_migration(connection, REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION)
    _migrate_v7_schema(connection)
    _migrate_v8_schema(connection)


def _migrate_legacy_schema(connection: Connection) -> None:
    _lock_legacy_migration_writes(connection)
    _assert_replay_authority_can_be_rebuilt(connection, schema_version=1)
    Base.metadata.tables[SchemaVersionRecord.__tablename__].create(connection, checkfirst=False)
    _record_migration(connection, LEGACY_SCHEMA_VERSION)
    _install_v2_job_binding_index(connection)
    _record_migration(connection, REPLAY_AUTHORITY_SCHEMA_VERSION)
    _create_tables(connection, ARTIFACT_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_artifacts")
    _record_migration(connection, ARTIFACT_AUTHORITY_SCHEMA_VERSION)
    _create_current_replay_authority(connection)
    _record_migration(connection, REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION)
    _record_migration(connection, DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION)
    _record_migration(connection, REPLAY_TOOL_PERMIT_SCHEMA_VERSION)
    _record_migration(connection, REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION)
    _migrate_v7_schema(connection)
    _migrate_v8_schema(connection)


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
    _record_migration(connection, ARTIFACT_AUTHORITY_SCHEMA_VERSION)
    _create_current_replay_authority(connection)
    _record_migration(connection, REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION)
    _record_migration(connection, DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION)
    _record_migration(connection, REPLAY_TOOL_PERMIT_SCHEMA_VERSION)
    _record_migration(connection, REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION)
    _migrate_v7_schema(connection)
    _migrate_v8_schema(connection)


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
    _create_current_replay_authority(connection)
    _record_migration(connection, REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION)
    _record_migration(connection, DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION)
    _record_migration(connection, REPLAY_TOOL_PERMIT_SCHEMA_VERSION)
    _record_migration(connection, REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION)
    _migrate_v7_schema(connection)
    _migrate_v8_schema(connection)


def _migrate_v4_schema(connection: Connection) -> None:
    """Preserve non-dispatchable proof rows while adding durable permit authority."""

    _lock_v4_migration_writes(connection)
    _assert_v4_replay_authority_is_non_dispatchable(connection)

    compilation_table = _V4_METADATA.tables[ReplayCompilationRecord.__tablename__]
    event_table = _V4_METADATA.tables[ReplayEventRecord.__tablename__]
    compilation_rows = [
        dict(row) for row in connection.execute(compilation_table.select()).mappings()
    ]
    event_rows = [dict(row) for row in connection.execute(event_table.select()).mappings()]

    _remove_append_only_trigger_support(connection, "cp_replay_events")
    _remove_append_only_trigger_support(connection, "cp_replay_compilations")
    for table_name in (
        "cp_replay_events",
        "cp_replay_tickets",
        "cp_replay_compilations",
    ):
        connection.exec_driver_sql(f"DROP TABLE {table_name}")

    _create_tables(connection, REPLAY_COMPILATION_AUTHORITY_TABLES)
    if compilation_rows:
        connection.execute(
            Base.metadata.tables[ReplayCompilationRecord.__tablename__].insert(),
            compilation_rows,
        )
    _install_append_only_trigger(connection, "cp_replay_compilations")
    _create_replay_permit_and_ticket_tables(connection)
    _create_tables(connection, frozenset({ReplayEventRecord.__tablename__}))
    if event_rows:
        connection.execute(
            Base.metadata.tables[ReplayEventRecord.__tablename__].insert(),
            event_rows,
        )
    _install_append_only_trigger(connection, "cp_replay_events")
    _record_migration(connection, DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION)
    _create_replay_tool_permit_authority(connection)
    _record_migration(connection, REPLAY_TOOL_PERMIT_SCHEMA_VERSION)
    _create_replay_execution_context_authority(connection)
    _record_migration(connection, REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION)
    _migrate_v7_schema(connection)
    _migrate_v8_schema(connection)


def _assert_v4_replay_authority_is_non_dispatchable(connection: Connection) -> None:
    """Reject v4 data that cannot be assigned honest durable reservations."""

    ticket_count = int(connection.scalar(text("SELECT count(*) FROM cp_replay_tickets")) or 0)
    internal_replay_jobs = int(
        connection.scalar(text("SELECT count(*) FROM cp_jobs WHERE kind = 'internal-replay'")) or 0
    )
    replay_run_jobs = int(
        connection.scalar(
            text(
                "SELECT count(*) FROM cp_jobs AS jobs "
                "JOIN cp_replay_items AS items ON jobs.run_id = items.replay_run_id"
            )
        )
        or 0
    )
    non_planned_batches = int(
        connection.scalar(text("SELECT count(*) FROM cp_replay_batches WHERE state <> 'planned'"))
        or 0
    )
    advanced_items = int(
        connection.scalar(
            text("SELECT count(*) FROM cp_replay_items WHERE state <> 'pending' OR attempts <> 0")
        )
        or 0
    )
    if (
        ticket_count
        or internal_replay_jobs
        or replay_run_jobs
        or non_planned_batches
        or advanced_items
    ):
        raise SchemaInitializationError(
            "schema v4 contains dispatchable Replay authority without durable permits and "
            "cannot be trusted or backfilled "
            f"(tickets={ticket_count}, internal-replay Jobs={internal_replay_jobs}, "
            f"Replay Run Jobs={replay_run_jobs}, "
            f"non-planned batches={non_planned_batches}, advanced items={advanced_items})"
        )


def _migrate_v5_schema(connection: Connection) -> None:
    """Add per-call authority without inventing missing historical permits."""

    _lock_v5_migration_writes(connection)
    _assert_v5_replay_authority_has_no_unproven_consumption(connection)
    _create_replay_tool_permit_authority(connection)
    _assert_v6_replay_authority_is_non_dispatchable(connection)
    _record_migration(connection, REPLAY_TOOL_PERMIT_SCHEMA_VERSION)
    _create_replay_execution_context_authority(connection)
    _record_migration(connection, REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION)
    _migrate_v7_schema(connection)
    _migrate_v8_schema(connection)


def _migrate_v6_schema(connection: Connection) -> None:
    """Add an empty context authority without inventing historical context bytes."""

    _lock_v6_migration_writes(connection)
    _assert_v6_replay_authority_is_non_dispatchable(connection)
    _create_replay_execution_context_authority(connection)
    _record_migration(connection, REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION)
    _migrate_v7_schema(connection)
    _migrate_v8_schema(connection)


def _migrate_v7_schema(connection: Connection) -> None:
    """Atomically add the missing INSERT/REPLACE and TRUNCATE guards."""

    _lock_v7_migration_writes(connection)
    for table_name in sorted(V7_CONTROL_PLANE_TABLES & _APPEND_ONLY_TABLE_SUFFIXES.keys()):
        _install_complete_append_only_guard(connection, table_name)
    _record_migration(connection, COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION)


def _migrate_v8_schema(connection: Connection) -> None:
    """Add the append-only server-derived Replay finalization authority."""

    _lock_v7_migration_writes(connection)
    _create_tables(connection, REPLAY_FINALIZATION_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, ReplayFinalizationRecord.__tablename__)
    _install_complete_append_only_guard(connection, ReplayFinalizationRecord.__tablename__)
    _record_migration(connection, REPLAY_FINALIZATION_SCHEMA_VERSION)
    _migrate_v9_schema(connection)


def _migrate_v9_schema(connection: Connection) -> None:
    """Persist exact submission identity and a finite server lease horizon."""

    _lock_v9_migration_writes(connection)
    _validate_migrating_core_json_rows(connection)
    run_columns = {column["name"] for column in inspect(connection).get_columns("cp_runs")}
    job_columns = {column["name"] for column in inspect(connection).get_columns("cp_jobs")}
    new_run_columns = {"submission_authority_digest"}
    new_job_columns = {
        "submission_authority_digest",
        "lease_deadline_at",
        "heartbeat_event_at",
    }
    present_run_columns = run_columns & new_run_columns
    present_job_columns = job_columns & new_job_columns
    if present_run_columns not in (set(), new_run_columns) or present_job_columns not in (
        set(),
        new_job_columns,
    ):
        raise SchemaInitializationError("schema v9 contains a partial v10 authority migration")

    if not present_run_columns:
        connection.exec_driver_sql(
            "ALTER TABLE cp_runs ADD COLUMN submission_authority_digest VARCHAR(64)"
        )
    if not present_job_columns:
        timestamp_type = DateTime(timezone=True).compile(dialect=connection.dialect)
        connection.exec_driver_sql(
            "ALTER TABLE cp_jobs ADD COLUMN submission_authority_digest VARCHAR(64)"
        )
        connection.exec_driver_sql(
            f"ALTER TABLE cp_jobs ADD COLUMN lease_deadline_at {timestamp_type}"
        )
        connection.exec_driver_sql(
            f"ALTER TABLE cp_jobs ADD COLUMN heartbeat_event_at {timestamp_type}"
        )

    _backfill_submission_authority_digests(connection)
    _backfill_job_submission_authority_digests(connection)
    _backfill_lease_authority(connection)
    _install_submission_and_lease_authority_guards(connection)
    _record_migration(connection, SUBMISSION_AND_LEASE_AUTHORITY_SCHEMA_VERSION)
    _migrate_v10_schema(connection)


def _migrate_v10_schema(connection: Connection) -> None:
    """Add append-only authority for one immutable projection per Replay batch."""

    _lock_v9_migration_writes(connection)
    _create_tables(connection, REPLAY_PROJECTION_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, ReplayProjectionRecord.__tablename__)
    _install_complete_append_only_guard(connection, ReplayProjectionRecord.__tablename__)
    _record_migration(connection, REPLAY_PROJECTION_AUTHORITY_SCHEMA_VERSION)
    _migrate_v11_schema(connection)


def _migrate_v11_schema(connection: Connection) -> None:
    """Bind one immutable parent Retest Artifact to every negative batch."""

    _lock_v9_migration_writes(connection)
    _create_tables(connection, REPLAY_RETEST_SOURCE_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, ReplayRetestSourceRecord.__tablename__)
    _install_complete_append_only_guard(connection, ReplayRetestSourceRecord.__tablename__)
    _record_migration(connection, REPLAY_RETEST_SOURCE_AUTHORITY_SCHEMA_VERSION)
    _migrate_v12_schema(connection)


def _migrate_v12_schema(connection: Connection) -> None:
    """Add append-only exact Claim identity without rewriting existing Replay rows."""

    _lock_v9_migration_writes(connection)
    _create_tables(connection, REPLAY_CLAIM_PROJECTION_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, ReplayClaimBindingRecord.__tablename__)
    _install_complete_append_only_guard(connection, ReplayClaimBindingRecord.__tablename__)
    _record_migration(connection, REPLAY_CLAIM_PROJECTION_SCHEMA_VERSION)
    _migrate_v13_schema(connection)


def _migrate_v13_schema(connection: Connection) -> None:
    """Add the durable monotonic activation ledger for signed Target registries."""

    _lock_v9_migration_writes(connection)
    _create_tables(connection, TARGET_ATTESTATION_REGISTRY_AUTHORITY_TABLES)
    _install_append_only_trigger(
        connection,
        TargetAttestationRegistryVersionRecord.__tablename__,
    )
    _install_complete_append_only_guard(
        connection,
        TargetAttestationRegistryVersionRecord.__tablename__,
    )
    _record_migration(connection, TARGET_ATTESTATION_REGISTRY_SCHEMA_VERSION)


def _validate_migrating_core_json_rows(connection: Connection) -> None:
    """Fail closed before legacy JSON result processors can hydrate malformed rows."""

    try:
        for table_name in (
            RunRecord.__tablename__,
            JobRecord.__tablename__,
            EventRecord.__tablename__,
        ):
            table = _V9_METADATA.tables[table_name]
            _validate_json_authority_columns(connection, table)
            if connection.dialect.name == "sqlite":
                _validate_sqlite_datetime_columns(connection, table)
    except SchemaInitializationError as exc:
        raise SchemaInitializationError(
            "legacy Control Plane core row authority is invalid"
        ) from exc


def _backfill_submission_authority_digests(connection: Connection) -> None:
    """Backfill only reconstructable v9 submissions; fence every ambiguous legacy row."""

    run_table = _V9_METADATA.tables[RunRecord.__tablename__]
    job_table = _V9_METADATA.tables[JobRecord.__tablename__]
    event_table = _V9_METADATA.tables[EventRecord.__tablename__]
    current_run_table = cast(Table, RunRecord.__table__)
    last_run_id: str | None = None
    while True:
        statement = (
            select(
                run_table.c.run_id,
                run_table.c.campaign_name,
                run_table.c.input,
                run_table.c.submission_key,
            )
            .order_by(run_table.c.run_id)
            .limit(_JSON_AUTHORITY_BATCH_SIZE)
        )
        if last_run_id is not None:
            statement = statement.where(run_table.c.run_id > last_run_id)
        runs = list(connection.execute(statement).mappings())
        if not runs:
            return

        run_ids = [str(run["run_id"]) for run in runs]
        submission_keys = [f"submission:{run['submission_key']}" for run in runs]
        jobs_by_idempotency_key = {
            str(row["idempotency_key"]): row
            for row in connection.execute(
                select(
                    job_table.c.job_id,
                    job_table.c.run_id,
                    job_table.c.kind,
                    job_table.c.payload,
                    job_table.c.max_attempts,
                    job_table.c.idempotency_key,
                ).where(job_table.c.idempotency_key.in_(submission_keys))
            ).mappings()
        }
        submitted_events = {
            str(row["run_id"]): row
            for row in connection.execute(
                select(
                    event_table.c.run_id,
                    event_table.c.actor,
                    event_table.c.payload,
                ).where(
                    event_table.c.run_id.in_(run_ids),
                    event_table.c.sequence == 1,
                    event_table.c.event_type == "run.submitted",
                )
            ).mappings()
        }
        for run in runs:
            run_id = str(run["run_id"])
            submission_key = str(run["submission_key"])
            job = jobs_by_idempotency_key.get(f"submission:{submission_key}")
            submitted = submitted_events.get(run_id)
            authority_digest = _reconstruct_submission_authority_digest(
                run=run,
                job=job,
                submitted=submitted,
            )
            connection.execute(
                current_run_table.update()
                .where(current_run_table.c.run_id == run_id)
                .values(submission_authority_digest=authority_digest)
            )
        last_run_id = run_ids[-1]


def _reconstruct_submission_authority_digest(
    *,
    run: Any,
    job: Any | None,
    submitted: Any | None,
) -> str:
    """Return a public replay digest only for one exactly proven v9 authority graph."""

    run_id = str(run["run_id"])
    if job is not None and submitted is not None:
        event_payload = submitted["payload"]
        expected_job_payload = {"input": run["input"]}
        if (
            isinstance(event_payload, dict)
            and str(job["run_id"]) == run_id
            and event_payload.get("campaignName") == run["campaign_name"]
            and event_payload.get("jobId") == job["job_id"]
            and event_payload.get("jobKind") == job["kind"]
            and job["payload"] == expected_job_payload
        ):
            try:
                return submission_authority_digest(
                    actor=str(submitted["actor"]),
                    campaign_name=str(run["campaign_name"]),
                    input_value=run["input"],
                    idempotency_key=str(run["submission_key"]),
                    job_kind=str(job["kind"]),
                    max_attempts=int(job["max_attempts"]),
                )
            except (TypeError, ValueError):
                pass
    return non_replayable_submission_authority_digest(
        run_id=run_id,
        authority_kind="legacy-unproven-v9",
    )


def _backfill_job_submission_authority_digests(connection: Connection) -> None:
    """Bind every pre-v10 Job's immutable dispatch tuple before writers resume."""

    job_table = _V9_METADATA.tables[JobRecord.__tablename__]
    current_job_table = cast(Table, JobRecord.__table__)
    last_job_id: Any | None = None
    while True:
        statement = (
            select(
                job_table.c.job_id,
                job_table.c.run_id,
                job_table.c.kind,
                job_table.c.payload,
                job_table.c.max_attempts,
                job_table.c.idempotency_key,
            )
            .order_by(job_table.c.job_id)
            .limit(_JSON_AUTHORITY_BATCH_SIZE)
        )
        if last_job_id is not None:
            statement = statement.where(job_table.c.job_id > last_job_id)
        jobs = list(connection.execute(statement).mappings())
        if not jobs:
            return
        for row in jobs:
            try:
                authority_digest = _job_submission_authority_digest_from_row(row)
            except (TypeError, ValueError) as exc:
                raise SchemaInitializationError(
                    f"legacy Job {row['job_id']!r} has unbindable submission authority"
                ) from exc
            connection.execute(
                current_job_table.update()
                .where(current_job_table.c.job_id == row["job_id"])
                .values(submission_authority_digest=authority_digest)
            )
        last_job_id = str(jobs[-1]["job_id"])


def _job_submission_authority_digest_from_row(row: Any) -> str:
    return job_submission_authority_digest(
        job_id=row["job_id"],
        run_id=row["run_id"],
        job_kind=row["kind"],
        payload=row["payload"],
        max_attempts=row["max_attempts"],
        idempotency_key=row["idempotency_key"],
    )


def _backfill_lease_authority(connection: Connection) -> None:
    """Cap pre-v10 active leases at their already-issued expiry without minting time."""

    job_table = _V9_METADATA.tables[JobRecord.__tablename__]
    current_job_table = cast(Table, JobRecord.__table__)
    migration_time = utc_now()
    last_job_id: str | None = None
    while True:
        statement = (
            select(
                job_table.c.job_id,
                job_table.c.state,
                job_table.c.lease_expires_at,
                job_table.c.heartbeat_at,
            )
            .order_by(job_table.c.job_id)
            .limit(_MIGRATION_BACKFILL_BATCH_SIZE)
        )
        if last_job_id is not None:
            statement = statement.where(job_table.c.job_id > last_job_id)
        jobs = list(connection.execute(statement).mappings())
        if not jobs:
            return
        for row in jobs:
            leased = row["state"] == "leased"
            lease_deadline = row["lease_expires_at"] if leased else None
            if leased and lease_deadline is None:
                lease_deadline = migration_time
            connection.execute(
                current_job_table.update()
                .where(current_job_table.c.job_id == row["job_id"])
                .values(
                    lease_deadline_at=lease_deadline,
                    heartbeat_event_at=row["heartbeat_at"] if leased else None,
                )
            )
        last_job_id = str(jobs[-1]["job_id"])


def _assert_v6_replay_authority_is_non_dispatchable(connection: Connection) -> None:
    """Reject v6 execution state whose exact Worker context cannot be backfilled."""

    tickets = int(connection.scalar(text("SELECT count(*) FROM cp_replay_tickets")) or 0)
    permits = int(connection.scalar(text("SELECT count(*) FROM cp_replay_tool_permits")) or 0)
    internal_replay_jobs = int(
        connection.scalar(text("SELECT count(*) FROM cp_jobs WHERE kind = 'internal-replay'")) or 0
    )
    replay_run_jobs = int(
        connection.scalar(
            text(
                "SELECT count(*) FROM cp_jobs AS jobs "
                "JOIN cp_replay_items AS items ON jobs.run_id = items.replay_run_id"
            )
        )
        or 0
    )
    budget_accounts = int(
        connection.scalar(text("SELECT count(*) FROM cp_replay_budget_accounts")) or 0
    )
    rate_accounts = int(
        connection.scalar(text("SELECT count(*) FROM cp_replay_rate_accounts")) or 0
    )
    budget_reservations = int(
        connection.scalar(text("SELECT count(*) FROM cp_replay_budget_reservations")) or 0
    )
    rate_reservations = int(
        connection.scalar(text("SELECT count(*) FROM cp_replay_rate_reservations")) or 0
    )
    non_planned_batches = int(
        connection.scalar(text("SELECT count(*) FROM cp_replay_batches WHERE state <> 'planned'"))
        or 0
    )
    advanced_items = int(
        connection.scalar(
            text("SELECT count(*) FROM cp_replay_items WHERE state <> 'pending' OR attempts <> 0")
        )
        or 0
    )
    if any(
        (
            tickets,
            permits,
            internal_replay_jobs,
            replay_run_jobs,
            budget_accounts,
            rate_accounts,
            budget_reservations,
            rate_reservations,
            non_planned_batches,
            advanced_items,
        )
    ):
        raise SchemaInitializationError(
            "schema v6 contains dispatchable Replay authority without exact execution "
            "context and cannot be trusted or backfilled "
            f"(tickets={tickets}, permits={permits}, "
            f"internal-replay Jobs={internal_replay_jobs}, "
            f"Replay Run Jobs={replay_run_jobs}, "
            f"budget accounts={budget_accounts}, rate accounts={rate_accounts}, "
            f"budget reservations={budget_reservations}, "
            f"rate reservations={rate_reservations}, "
            f"non-planned batches={non_planned_batches}, advanced items={advanced_items})"
        )


def _assert_v5_replay_authority_has_no_unproven_consumption(connection: Connection) -> None:
    """Reject execution state that schema v5 could not attribute to permit rows."""

    budget_account_consumption = int(
        connection.scalar(
            text("SELECT count(*) FROM cp_replay_budget_accounts WHERE consumed_calls <> 0")
        )
        or 0
    )
    budget_reservation_consumption = int(
        connection.scalar(
            text("SELECT count(*) FROM cp_replay_budget_reservations WHERE consumed_calls <> 0")
        )
        or 0
    )
    rate_reservation_consumption = int(
        connection.scalar(
            text(
                "SELECT count(*) FROM cp_replay_rate_reservations WHERE consumed_request_units <> 0"
            )
        )
        or 0
    )
    finalized_tickets = int(
        connection.scalar(text("SELECT count(*) FROM cp_replay_tickets WHERE state = 'finalized'"))
        or 0
    )
    succeeded_replay_jobs = int(
        connection.scalar(
            text(
                "SELECT count(*) FROM cp_jobs "
                "WHERE kind = 'internal-replay' AND state = 'succeeded'"
            )
        )
        or 0
    )
    executed_items = int(
        connection.scalar(
            text("SELECT count(*) FROM cp_replay_items WHERE state IN ('verified', 'gated')")
        )
        or 0
    )
    completed_batches = int(
        connection.scalar(
            text("SELECT count(*) FROM cp_replay_batches WHERE state IN ('gating', 'completed')")
        )
        or 0
    )
    if any(
        (
            budget_account_consumption,
            budget_reservation_consumption,
            rate_reservation_consumption,
            finalized_tickets,
            succeeded_replay_jobs,
            executed_items,
            completed_batches,
        )
    ):
        raise SchemaInitializationError(
            "schema v5 contains Replay execution or consumption without per-call permit proof "
            "and cannot be trusted or backfilled "
            f"(budget accounts={budget_account_consumption}, "
            f"budget reservations={budget_reservation_consumption}, "
            f"rate reservations={rate_reservation_consumption}, "
            f"finalized tickets={finalized_tickets}, "
            f"succeeded Replay Jobs={succeeded_replay_jobs}, "
            f"executed items={executed_items}, completed batches={completed_batches})"
        )


_LEGACY_MIGRATION_WRITE_LOCK_TABLES = ("cp_jobs",)
_V2_MIGRATION_WRITE_LOCK_TABLES = (
    "cp_jobs",
    "cp_replay_batches",
    "cp_replay_items",
    "cp_replay_tickets",
    "cp_replay_events",
)
_V3_MIGRATION_WRITE_LOCK_TABLES = _V2_MIGRATION_WRITE_LOCK_TABLES
_V4_MIGRATION_WRITE_LOCK_TABLES = (
    "cp_artifacts",
    "cp_runs",
    "cp_jobs",
    "cp_replay_tickets",
    "cp_replay_items",
    "cp_replay_batches",
    "cp_replay_compilations",
    "cp_replay_events",
    "cp_approvals",
    "cp_checkpoints",
    "cp_events",
    "cp_schema_version",
)
_V5_MIGRATION_WRITE_LOCK_TABLES = (
    "cp_jobs",
    "cp_replay_tickets",
    "cp_replay_items",
    "cp_replay_batches",
    "cp_replay_budget_accounts",
    "cp_replay_rate_accounts",
    "cp_replay_budget_reservations",
    "cp_replay_rate_reservations",
    "cp_replay_compilations",
    "cp_replay_events",
    "cp_approvals",
    "cp_checkpoints",
    "cp_artifacts",
    "cp_events",
    "cp_schema_version",
    "cp_runs",
)
_V6_MIGRATION_WRITE_LOCK_TABLES = (
    "cp_jobs",
    "cp_replay_tickets",
    "cp_replay_items",
    "cp_replay_batches",
    "cp_replay_budget_accounts",
    "cp_replay_rate_accounts",
    "cp_replay_budget_reservations",
    "cp_replay_rate_reservations",
    "cp_replay_compilations",
    "cp_replay_tool_permits",
    "cp_replay_events",
    "cp_approvals",
    "cp_checkpoints",
    "cp_artifacts",
    "cp_events",
    "cp_schema_version",
    "cp_runs",
)
_V7_MIGRATION_WRITE_LOCK_TABLES = (
    "cp_jobs",
    "cp_replay_tickets",
    "cp_replay_items",
    "cp_replay_batches",
    "cp_replay_budget_accounts",
    "cp_replay_rate_accounts",
    "cp_replay_budget_reservations",
    "cp_replay_rate_reservations",
    "cp_replay_compilations",
    "cp_replay_execution_contexts",
    "cp_replay_tool_permits",
    "cp_replay_events",
    "cp_approvals",
    "cp_checkpoints",
    "cp_artifacts",
    "cp_events",
    "cp_schema_version",
    "cp_runs",
)
_V9_MIGRATION_WRITE_LOCK_TABLES = (
    "cp_runs",
    "cp_jobs",
    "cp_events",
    "cp_schema_version",
)
_V4_MIGRATION_LOCK_RETRY_SECONDS = 0.05
_V4_MIGRATION_LOCK_TIMEOUT_SECONDS = 5.0


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

    _lock_migration_writes(
        connection,
        table_names=_V2_MIGRATION_WRITE_LOCK_TABLES,
        schema_version=2,
        retry_on_contention=False,
    )


def _lock_v3_migration_writes(connection: Connection) -> None:
    """Exclude v3 writers from the canonical-compilation authority check."""

    _lock_migration_writes(
        connection,
        table_names=_V3_MIGRATION_WRITE_LOCK_TABLES,
        schema_version=3,
        retry_on_contention=False,
    )


def _lock_v4_migration_writes(connection: Connection) -> None:
    """Atomically exclude every v4 writer without waiting on a partial lock set."""

    _lock_migration_writes(
        connection,
        table_names=_V4_MIGRATION_WRITE_LOCK_TABLES,
        schema_version=4,
        retry_on_contention=True,
    )


def _lock_v5_migration_writes(connection: Connection) -> None:
    """Atomically exclude every v5 writer before checking consumption history."""

    _lock_migration_writes(
        connection,
        table_names=_V5_MIGRATION_WRITE_LOCK_TABLES,
        schema_version=5,
        retry_on_contention=True,
    )


def _lock_v6_migration_writes(connection: Connection) -> None:
    """Atomically exclude every v6 writer before proving non-dispatchability."""

    _lock_migration_writes(
        connection,
        table_names=_V6_MIGRATION_WRITE_LOCK_TABLES,
        schema_version=6,
        retry_on_contention=True,
    )


def _lock_v7_migration_writes(connection: Connection) -> None:
    """Atomically exclude every v7 writer while all guards become complete."""

    _lock_migration_writes(
        connection,
        table_names=_V7_MIGRATION_WRITE_LOCK_TABLES,
        schema_version=7,
        retry_on_contention=True,
    )


def _lock_v9_migration_writes(connection: Connection) -> None:
    """Atomically exclude submission, lease, event, and migration-history writers."""

    _lock_migration_writes(
        connection,
        table_names=_V9_MIGRATION_WRITE_LOCK_TABLES,
        schema_version=9,
        retry_on_contention=True,
    )


def _lock_migration_writes(
    connection: Connection,
    *,
    table_names: tuple[str, ...],
    schema_version: int,
    retry_on_contention: bool,
) -> None:
    """Acquire one versioned writer lock set without changing transaction ownership."""

    if connection.dialect.name == "sqlite":
        # ``initialize`` acquired BEGIN IMMEDIATE before inspecting the table set.
        return
    if connection.dialect.name != "postgresql":
        raise SchemaInitializationError(
            f"unsupported Control Plane database dialect: {connection.dialect.name}"
        )

    tables = ", ".join(table_names)
    statement = f"LOCK TABLE {tables} IN ACCESS EXCLUSIVE MODE"
    if not retry_on_contention:
        connection.exec_driver_sql(statement)
        return

    statement += " NOWAIT"
    deadline = time.monotonic() + _V4_MIGRATION_LOCK_TIMEOUT_SECONDS
    while True:
        # Writers do not share one table order. A blocking multi-table LOCK can
        # deadlock after acquiring only a prefix, so each NOWAIT attempt gets a
        # savepoint that releases every partial lock before the retry. Committing
        # the successful savepoint promotes the complete set to the outer migration.
        savepoint = connection.begin_nested()
        try:
            connection.exec_driver_sql(statement)
        except DBAPIError as error:
            savepoint.rollback()
            sqlstate = getattr(error.orig, "sqlstate", None) or getattr(error.orig, "pgcode", None)
            if sqlstate != "55P03":
                raise
            if time.monotonic() >= deadline:
                raise SchemaInitializationError(
                    f"schema v{schema_version} migration could not exclude active writers; "
                    "retry initialization after current transactions finish"
                ) from error
            time.sleep(_V4_MIGRATION_LOCK_RETRY_SECONDS)
        else:
            savepoint.commit()
            return


def _create_current_replay_authority(connection: Connection) -> None:
    """Create current Replay tables in an explicit cross-dialect FK order."""

    _create_tables(connection, frozenset({ReplayBatchRecord.__tablename__}))
    _create_tables(connection, frozenset({ReplayItemRecord.__tablename__}))
    _create_tables(connection, REPLAY_COMPILATION_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, "cp_replay_compilations")
    _create_replay_permit_and_ticket_tables(connection)
    _create_tables(connection, frozenset({ReplayEventRecord.__tablename__}))
    _install_append_only_trigger(connection, "cp_replay_events")
    _create_replay_tool_permit_authority(connection)
    _create_replay_execution_context_authority(connection)


def _create_replay_permit_and_ticket_tables(connection: Connection) -> None:
    """Create mutable permit ledgers before the ticket FKs that consume them."""

    for table_name in (
        ReplayBudgetAccountRecord.__tablename__,
        ReplayRateAccountRecord.__tablename__,
        ReplayBudgetReservationRecord.__tablename__,
        ReplayRateReservationRecord.__tablename__,
        ReplayTicketRecord.__tablename__,
    ):
        _create_tables(connection, frozenset({table_name}))


def _create_replay_tool_permit_authority(connection: Connection) -> None:
    """Create the append-only per-call consumption ledger after its exact parents."""

    _install_v6_ticket_permit_binding_index(connection)
    _create_tables(connection, REPLAY_TOOL_PERMIT_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, ReplayToolPermitRecord.__tablename__)


def _create_replay_execution_context_authority(connection: Connection) -> None:
    """Create append-only exact Worker context after its compilation parent."""

    _create_tables(connection, REPLAY_EXECUTION_CONTEXT_AUTHORITY_TABLES)
    _install_append_only_trigger(connection, ReplayExecutionContextRecord.__tablename__)


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


def _install_v6_ticket_permit_binding_index(connection: Connection) -> None:
    """Install the exact claimed-ticket key referenced by append-only permits."""

    index_name = str(_replay_ticket_permit_authority_index.name)
    indexes = {index["name"] for index in inspect(connection).get_indexes("cp_replay_tickets")}
    if index_name in indexes:
        return
    _replay_ticket_permit_authority_index.create(connection, checkfirst=False)


def _record_migration(connection: Connection, version: int) -> None:
    schema_version = Base.metadata.tables[SchemaVersionRecord.__tablename__]
    connection.execute(
        schema_version.insert().values(
            version=version,
            description=_MIGRATIONS[version],
            applied_at=utc_now(),
        )
    )


def _latest_schema_version(connection: Connection) -> int | None:
    try:
        version = connection.scalar(text("SELECT max(version) FROM cp_schema_version"))
    except DBAPIError as exc:
        raise SchemaInitializationError("cp_schema_version cannot be inspected safely") from exc
    return None if version is None else int(version)


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
    _validate_tables(
        connection,
        CURRENT_CONTROL_PLANE_TABLES,
        append_only_guard_version=COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
        require_submission_and_lease_guards=True,
    )
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
    _validate_v10_authority_rows(connection)


def _validate_v7_schema(connection: Connection) -> None:
    _validate_tables(
        connection,
        V7_CONTROL_PLANE_TABLES,
        metadata=_V7_METADATA,
        append_only_guard_version=REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION,
    )
    rows = connection.execute(
        select(
            SchemaVersionRecord.version,
            SchemaVersionRecord.description,
            SchemaVersionRecord.applied_at,
        ).order_by(SchemaVersionRecord.version)
    ).all()
    expected = [
        (version, _MIGRATIONS[version])
        for version in range(LEGACY_SCHEMA_VERSION, REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION + 1)
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v7 migration history: {actual!r}"
        )


def _validate_v8_schema(connection: Connection) -> None:
    _validate_tables(
        connection,
        V8_CONTROL_PLANE_TABLES,
        metadata=_V7_METADATA,
        append_only_guard_version=COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
    )
    rows = connection.execute(
        select(
            SchemaVersionRecord.version,
            SchemaVersionRecord.description,
            SchemaVersionRecord.applied_at,
        ).order_by(SchemaVersionRecord.version)
    ).all()
    expected = [
        (version, _MIGRATIONS[version])
        for version in range(
            LEGACY_SCHEMA_VERSION,
            COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION + 1,
        )
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v8 migration history: {actual!r}"
        )


def _validate_v9_schema(connection: Connection) -> None:
    _validate_tables(
        connection,
        V10_CONTROL_PLANE_TABLES,
        metadata=_V9_METADATA,
        append_only_guard_version=COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
    )
    rows = connection.execute(
        select(
            SchemaVersionRecord.version,
            SchemaVersionRecord.description,
            SchemaVersionRecord.applied_at,
        ).order_by(SchemaVersionRecord.version)
    ).all()
    expected = [
        (version, _MIGRATIONS[version])
        for version in range(LEGACY_SCHEMA_VERSION, REPLAY_FINALIZATION_SCHEMA_VERSION + 1)
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v9 migration history: {actual!r}"
        )


def _validate_v10_schema(connection: Connection) -> None:
    _validate_tables(
        connection,
        V10_CONTROL_PLANE_TABLES,
        metadata=_V10_METADATA,
        append_only_guard_version=COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
        require_submission_and_lease_guards=True,
    )
    rows = connection.execute(
        select(
            SchemaVersionRecord.version,
            SchemaVersionRecord.description,
            SchemaVersionRecord.applied_at,
        ).order_by(SchemaVersionRecord.version)
    ).all()
    expected = [
        (version, _MIGRATIONS[version])
        for version in range(
            LEGACY_SCHEMA_VERSION,
            SUBMISSION_AND_LEASE_AUTHORITY_SCHEMA_VERSION + 1,
        )
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v10 migration history: {actual!r}"
        )
    _validate_v10_authority_rows(connection)


def _validate_v11_schema(connection: Connection) -> None:
    _validate_tables(
        connection,
        V11_CONTROL_PLANE_TABLES,
        metadata=_V11_METADATA,
        append_only_guard_version=COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
        require_submission_and_lease_guards=True,
    )
    rows = connection.execute(
        select(
            SchemaVersionRecord.version,
            SchemaVersionRecord.description,
            SchemaVersionRecord.applied_at,
        ).order_by(SchemaVersionRecord.version)
    ).all()
    expected = [
        (version, _MIGRATIONS[version])
        for version in range(LEGACY_SCHEMA_VERSION, REPLAY_PROJECTION_AUTHORITY_SCHEMA_VERSION + 1)
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v11 migration history: {actual!r}"
        )
    _validate_v10_authority_rows(connection)


def _validate_v12_schema(connection: Connection) -> None:
    _validate_tables(
        connection,
        V12_CONTROL_PLANE_TABLES,
        metadata=_V12_METADATA,
        append_only_guard_version=COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
        require_submission_and_lease_guards=True,
    )
    rows = connection.execute(
        select(
            SchemaVersionRecord.version,
            SchemaVersionRecord.description,
            SchemaVersionRecord.applied_at,
        ).order_by(SchemaVersionRecord.version)
    ).all()
    expected = [
        (version, _MIGRATIONS[version])
        for version in range(
            LEGACY_SCHEMA_VERSION,
            REPLAY_RETEST_SOURCE_AUTHORITY_SCHEMA_VERSION + 1,
        )
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v12 migration history: {actual!r}"
        )
    _validate_v10_authority_rows(connection)


def _validate_v13_schema(connection: Connection) -> None:
    _validate_tables(
        connection,
        V13_CONTROL_PLANE_TABLES,
        metadata=_V13_METADATA,
        append_only_guard_version=COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
        require_submission_and_lease_guards=True,
    )
    rows = connection.execute(
        select(
            SchemaVersionRecord.version,
            SchemaVersionRecord.description,
            SchemaVersionRecord.applied_at,
        ).order_by(SchemaVersionRecord.version)
    ).all()
    expected = [
        (version, _MIGRATIONS[version])
        for version in range(
            LEGACY_SCHEMA_VERSION,
            REPLAY_CLAIM_PROJECTION_SCHEMA_VERSION + 1,
        )
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v13 migration history: {actual!r}"
        )
    _validate_v10_authority_rows(connection)


def _validate_v10_authority_rows(connection: Connection) -> None:
    invalid_submission_digests = int(
        connection.scalar(
            text(
                "SELECT count(*) FROM cp_runs "
                "WHERE NOT ("
                + _run_authority_is_valid_sql(
                    "",
                    dialect_name=connection.dialect.name,
                )
                + ")"
            )
        )
        or 0
    )
    invalid_lease_authority = int(
        connection.scalar(
            text(
                "SELECT count(*) FROM cp_jobs WHERE "
                + _lease_authority_is_invalid_sql(
                    "",
                    dialect_name=connection.dialect.name,
                )
            )
        )
        or 0
    )
    invalid_job_bindings = (
        0
        if invalid_lease_authority
        else _count_invalid_job_submission_authority_bindings(connection)
    )
    invalid_run_resources = (
        0
        if invalid_submission_digests
        else _count_invalid_run_input_resources(
            connection,
            cast(Table, RunRecord.__table__),
        )
    )
    invalid_authority_rowids = 0
    if connection.dialect.name == "sqlite":
        invalid_authority_rowids = sum(
            int(connection.scalar(text(f"SELECT count(*) FROM {table_name} WHERE rowid <= 0")) or 0)
            for table_name in (RunRecord.__tablename__, JobRecord.__tablename__)
        )
    if (
        invalid_submission_digests
        or invalid_run_resources
        or invalid_lease_authority
        or invalid_job_bindings
        or invalid_authority_rowids
    ):
        raise SchemaInitializationError(
            "Control Plane v10 authority rows are inconsistent "
            f"(submission digests={invalid_submission_digests}, "
            f"run resources={invalid_run_resources}, "
            f"lease rows={invalid_lease_authority}, "
            f"job bindings={invalid_job_bindings}, "
            f"rowids={invalid_authority_rowids})"
        )


def _count_invalid_run_input_resources(
    connection: Connection,
    run_table: Table,
) -> int:
    """Validate every Run input against the public submission resource contract."""

    last_run_id: Any | None = None
    invalid = 0
    while True:
        statement = (
            select(run_table.c.run_id, run_table.c.input)
            .order_by(run_table.c.run_id)
            .limit(_JSON_AUTHORITY_BATCH_SIZE)
        )
        if last_run_id is not None:
            statement = statement.where(run_table.c.run_id > last_run_id)
        rows = list(connection.execute(statement).mappings())
        if not rows:
            return invalid
        for row in rows:
            try:
                validate_bounded_json_object(
                    row["input"],
                    policy=SUBMIT_RUN_INPUT_JSON_POLICY,
                )
            except (TypeError, ValueError):
                invalid += 1
        last_run_id = rows[-1]["run_id"]


def _count_invalid_job_submission_authority_bindings(connection: Connection) -> int:
    """Recompute each Job digest so a well-shaped but false marker cannot dispatch."""

    job_table = cast(Table, JobRecord.__table__)
    last_job_id: Any | None = None
    invalid = 0
    while True:
        statement = (
            select(
                job_table.c.job_id,
                job_table.c.run_id,
                job_table.c.kind,
                job_table.c.payload,
                job_table.c.max_attempts,
                job_table.c.idempotency_key,
                job_table.c.submission_authority_digest,
            )
            .order_by(job_table.c.job_id)
            .limit(_JSON_AUTHORITY_BATCH_SIZE)
        )
        if last_job_id is not None:
            statement = statement.where(job_table.c.job_id > last_job_id)
        rows = list(connection.execute(statement).mappings())
        if not rows:
            return invalid
        for row in rows:
            try:
                expected = _job_submission_authority_digest_from_row(row)
            except (TypeError, ValueError):
                invalid += 1
            else:
                if row["submission_authority_digest"] != expected:
                    invalid += 1
        last_job_id = rows[-1]["job_id"]


def _validate_v2_schema(connection: Connection) -> None:
    _validate_tables(
        connection,
        V2_CONTROL_PLANE_TABLES,
        metadata=_V2_METADATA,
        append_only_guard_version=REPLAY_AUTHORITY_SCHEMA_VERSION,
    )
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
    _validate_tables(
        connection,
        V3_CONTROL_PLANE_TABLES,
        metadata=_V3_METADATA,
        append_only_guard_version=ARTIFACT_AUTHORITY_SCHEMA_VERSION,
    )
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


def _validate_v4_schema(connection: Connection) -> None:
    _validate_tables(
        connection,
        V4_CONTROL_PLANE_TABLES,
        metadata=_V4_METADATA,
        append_only_guard_version=REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION,
    )
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
            REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION,
        )
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v4 migration history: {actual!r}"
        )


def _validate_v5_schema(connection: Connection) -> None:
    _validate_tables(
        connection,
        V5_CONTROL_PLANE_TABLES,
        metadata=_V5_METADATA,
        append_only_guard_version=DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION,
    )
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
            REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION,
            DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION,
        )
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v5 migration history: {actual!r}"
        )


def _validate_v6_schema(connection: Connection) -> None:
    _validate_tables(
        connection,
        V6_CONTROL_PLANE_TABLES,
        metadata=_V6_METADATA,
        append_only_guard_version=REPLAY_TOOL_PERMIT_SCHEMA_VERSION,
    )
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
            REPLAY_COMPILATION_AUTHORITY_SCHEMA_VERSION,
            DURABLE_REPLAY_RESERVATION_SCHEMA_VERSION,
            REPLAY_TOOL_PERMIT_SCHEMA_VERSION,
        )
    ]
    actual = [(int(row.version), str(row.description)) for row in rows]
    if actual != expected or any(row.applied_at is None for row in rows):
        raise SchemaInitializationError(
            f"unknown or incomplete schema v6 migration history: {actual!r}"
        )


def _validate_tables(
    connection: Connection,
    table_names: frozenset[str],
    *,
    allow_missing_v2_job_index: bool = False,
    metadata: MetaData | None = None,
    append_only_guard_version: int = REPLAY_EXECUTION_CONTEXT_SCHEMA_VERSION,
    require_submission_and_lease_guards: bool = False,
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
            if actual.get("default") is not None and not _is_managed_postgres_sequence_default(
                connection,
                table_name=table_name,
                column_name=name,
                value=actual["default"],
            ):
                raise SchemaInitializationError(
                    f"{table_name}.{name} has an unmanaged server default"
                )
            if actual.get("computed") is not None or actual.get("identity") is not None:
                raise SchemaInitializationError(
                    f"{table_name}.{name} has unmanaged generated-column authority"
                )

        _validate_json_authority_columns(connection, expected)
        if connection.dialect.name == "sqlite":
            _validate_sqlite_datetime_columns(connection, expected)

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
    if connection.dialect.name == "sqlite":
        _validate_sqlite_managed_rows(connection, table_names)
    _validate_trigger_inventory(
        connection,
        table_names,
        append_only_guard_version=append_only_guard_version,
        require_submission_and_lease_guards=require_submission_and_lease_guards,
    )


def _validate_sqlite_managed_rows(
    connection: Connection,
    table_names: frozenset[str],
) -> None:
    """Scope SQLite integrity checks to PAJIN-managed Control Plane tables."""

    for table_name in sorted(table_names):
        integrity = connection.exec_driver_sql(f"PRAGMA quick_check('{table_name}')").first()
        if integrity is None or integrity[0] != "ok":
            raise SchemaInitializationError(
                f"SQLite Control Plane table {table_name} failed its integrity check"
            )
        violation = connection.exec_driver_sql(f"PRAGMA foreign_key_check('{table_name}')").first()
        if violation is not None:
            raise SchemaInitializationError(
                "SQLite Control Plane rows violate managed foreign-key authority"
            )


def _validate_json_authority_columns(connection: Connection, table: Table) -> None:
    """Validate raw JSON before ORM result processors can erase duplicates or fail."""

    for column in table.columns:
        if not isinstance(column.type, JSON):
            continue
        max_storage_bytes = (
            _RUN_JSON_STORAGE_MAX_BYTES
            if table.name == RunRecord.__tablename__ and column.name == "input"
            else _JOB_JSON_STORAGE_MAX_BYTES
        )
        valid_sql = _json_object_is_valid_sql(
            f'"{column.name}"',
            dialect_name=connection.dialect.name,
            max_storage_bytes=max_storage_bytes,
            allow_json_null=bool(column.nullable),
            max_depth=(
                SUBMIT_RUN_INPUT_JSON_POLICY.max_depth
                if table.name == RunRecord.__tablename__ and column.name == "input"
                else CONTROL_PLANE_STORED_JSON_POLICY.max_depth
            ),
            max_nodes=(
                SUBMIT_RUN_INPUT_JSON_POLICY.max_nodes
                if table.name == RunRecord.__tablename__ and column.name == "input"
                else CONTROL_PLANE_STORED_JSON_POLICY.max_nodes
            ),
            max_keys=(
                SUBMIT_RUN_INPUT_JSON_POLICY.max_keys
                if table.name == RunRecord.__tablename__ and column.name == "input"
                else CONTROL_PLANE_STORED_JSON_POLICY.max_keys
            ),
        )
        invalid = int(
            connection.scalar(
                text(
                    f'SELECT count(*) FROM "{table.name}" '
                    f'WHERE "{column.name}" IS NOT NULL AND NOT ({valid_sql})'
                )
            )
            or 0
        )
        if invalid:
            raise SchemaInitializationError(
                f"{table.name}.{column.name} contains invalid JSON authority rows"
            )

        policy = (
            SUBMIT_RUN_INPUT_JSON_POLICY
            if table.name == RunRecord.__tablename__ and column.name == "input"
            else CONTROL_PLANE_STORED_JSON_POLICY
        )
        raw_json = column.cast(Text).label("raw_json")
        statement = (
            select(raw_json)
            .where(column.is_not(None))
            .execution_options(
                stream_results=True,
                max_row_buffer=_JSON_AUTHORITY_BATCH_SIZE,
            )
        )
        result = connection.execute(statement)
        try:
            for partition in result.partitions(_JSON_AUTHORITY_BATCH_SIZE):
                for row in partition:
                    try:
                        decoded = _strict_json_object(
                            str(row.raw_json),
                            allow_null=bool(column.nullable),
                        )
                        if decoded is not None:
                            validate_bounded_json_object(decoded, policy=policy)
                    except (TypeError, ValueError) as exc:
                        raise SchemaInitializationError(
                            f"{table.name}.{column.name} violates its JSON resource contract"
                        ) from exc
        finally:
            result.close()


def _install_submission_and_lease_authority_guards(connection: Connection) -> None:
    """Reject late schema-v9 writes after the v10 migration lock is released."""

    if connection.dialect.name == "sqlite":
        for operation in ("INSERT", "UPDATE"):
            connection.exec_driver_sql(_sqlite_submission_authority_trigger_sql(operation))
            connection.exec_driver_sql(_sqlite_lease_authority_trigger_sql(operation))
        connection.exec_driver_sql(
            _sqlite_authority_delete_trigger_sql(
                RunRecord.__tablename__,
                _SUBMISSION_AUTHORITY_TRIGGER_NAME,
            )
        )
        connection.exec_driver_sql(
            _sqlite_authority_delete_trigger_sql(
                JobRecord.__tablename__,
                _LEASE_AUTHORITY_TRIGGER_NAME,
            )
        )
        connection.exec_driver_sql(
            _sqlite_authority_rowid_trigger_sql(
                RunRecord.__tablename__,
                _SUBMISSION_AUTHORITY_TRIGGER_NAME,
            )
        )
        connection.exec_driver_sql(
            _sqlite_authority_rowid_trigger_sql(
                JobRecord.__tablename__,
                _LEASE_AUTHORITY_TRIGGER_NAME,
            )
        )
        return
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            f"""
            CREATE FUNCTION {_SUBMISSION_AUTHORITY_FUNCTION_NAME}()
            RETURNS trigger LANGUAGE plpgsql AS $$
            {_postgres_submission_authority_function_source()}
            $$
            """
        )
        connection.exec_driver_sql(
            f"""
            CREATE TRIGGER {_SUBMISSION_AUTHORITY_TRIGGER_NAME}
            BEFORE INSERT OR UPDATE OR DELETE ON cp_runs
            FOR EACH ROW EXECUTE FUNCTION {_SUBMISSION_AUTHORITY_FUNCTION_NAME}()
            """
        )
        connection.exec_driver_sql(
            f"""
            CREATE FUNCTION {_LEASE_AUTHORITY_FUNCTION_NAME}()
            RETURNS trigger LANGUAGE plpgsql AS $$
            {_postgres_lease_authority_function_source()}
            $$
            """
        )
        connection.exec_driver_sql(
            f"""
            CREATE TRIGGER {_LEASE_AUTHORITY_TRIGGER_NAME}
            BEFORE INSERT OR UPDATE OR DELETE ON cp_jobs
            FOR EACH ROW EXECUTE FUNCTION {_LEASE_AUTHORITY_FUNCTION_NAME}()
            """
        )
        return
    raise SchemaInitializationError(
        f"unsupported Control Plane database dialect: {connection.dialect.name}"
    )


def _install_append_only_trigger(connection: Connection, table_name: str) -> None:
    """Install the schema-v7 UPDATE/DELETE guards."""

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


def _install_complete_append_only_guard(connection: Connection, table_name: str) -> None:
    """Add the schema-v8 guard that closes dialect-specific replacement paths."""

    if table_name not in _APPEND_ONLY_TABLE_SUFFIXES:
        raise ValueError(f"unsupported append-only table: {table_name}")
    if connection.dialect.name == "sqlite":
        connection.exec_driver_sql(_sqlite_no_replace_trigger_sql(table_name))
        return
    if connection.dialect.name == "postgresql":
        suffix = _APPEND_ONLY_TABLE_SUFFIXES[table_name]
        connection.exec_driver_sql(
            f"""
            CREATE TRIGGER {table_name}_no_truncate
            BEFORE TRUNCATE ON {table_name}
            FOR EACH STATEMENT EXECUTE FUNCTION pajin_cp_reject_{suffix}_mutation()
            """
        )
        return
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


def _enable_sqlite_safety_pragmas(dbapi_connection: Any, *_event_args: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA recursive_triggers=ON")
        cursor.execute("PRAGMA ignore_check_constraints=OFF")
        cursor.execute(f"PRAGMA busy_timeout={_SQLITE_BUSY_TIMEOUT_MILLISECONDS}")
    finally:
        cursor.close()
