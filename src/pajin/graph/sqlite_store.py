"""Durable single-Campaign SQLite adapters for the Canonical Graph stores."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import tempfile
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from re import fullmatch
from typing import TYPE_CHECKING, Annotated, Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import StrictModel, ToolRiskTier
from pajin.graph.admission import (
    GraphAdmissionDecision,
    GraphAdmissionEvent,
    GraphEventLogError,
)
from pajin.graph.approval import (
    ActionApprovalAuthorization,
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ActionApprovalError,
    ActionApprovalInputAuthority,
    build_action_approval_consumption_receipt,
    validate_action_approval_authority,
)
from pajin.graph.approved_cleanup import (
    ApprovedReversibleActionError,
    ApprovedReversibleActionPermitAuthorization,
    validate_approved_reversible_action_authority,
)
from pajin.graph.authority import (
    ActionBudgetReservation,
    ActionCapabilityExecutionPolicyRegistry,
    ActionPermit,
    ActionPermitAuthorization,
    ActionPermitBudgetExceeded,
    ActionPermitConflict,
    ActionPermitError,
    ActionPermitStaleDecision,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
    action_permit_attempt_id,
    build_action_permit,
    validate_action_authority,
    validate_plain_action_policy,
)
from pajin.graph.cleanup import (
    ActionCleanupReservation,
    ActionCleanupReservationRequest,
    CleanupPermit,
    CleanupPermitAuthorization,
    CleanupPermitBudgetExceeded,
    CleanupPermitConflict,
    CleanupPermitError,
    CleanupPermitInputAuthority,
    CleanupPermitStaleDecision,
    CleanupRequest,
    ReversibleActionPermitAuthorization,
    ReversibleActionPermitInputAuthority,
    build_action_cleanup_reservation,
    build_cleanup_permit,
    cleanup_permit_attempt_id,
    validate_action_cleanup_reservation_authority,
    validate_cleanup_authority,
    validate_reversible_action_policy,
)
from pajin.graph.consistency import GraphDecision
from pajin.graph.models import (
    GraphNode,
    GraphNodeKind,
    canonical_graph_json,
    parse_graph_node,
)
from pajin.graph.projection import (
    GraphProjection,
    GraphProjectionAdvanceResult,
    GraphProjectionConflict,
    GraphProjectionError,
    GraphProjector,
    GraphSnapshot,
    GraphSnapshotError,
    GraphSnapshotRef,
    graph_snapshot_ref,
)
from pajin.runtime.safe_files import (
    parse_strict_json_bytes,
    read_bounded_regular_bytes,
)

if TYPE_CHECKING:
    from pajin.graph.backup_retention import (
        SQLiteGraphBackupSigner,
        SQLiteGraphBackupVerificationKey,
        SQLiteGraphRetainedBackupManifest,
    )

_SCHEMA_VERSION = 4
_CLEANUP_SCHEMA_VERSION = 3
_ACTION_PERMIT_SCHEMA_VERSION = 2
_LEGACY_SCHEMA_VERSION = 1
_APPLICATION_ID = 0x50414752  # ASCII "PAGR"
_BUSY_TIMEOUT_MS = 30_000
_MAX_GRAPH_BYTES = 64 * 1024 * 1024
_MAX_GRAPH_BACKUP_BYTES = 256 * 1024 * 1024
_MAX_GRAPH_BACKUP_MANIFEST_BYTES = 64 * 1024


def _canonical_action_policy_registry(
    policies: ActionCapabilityExecutionPolicyRegistry,
    *,
    label: str,
) -> ActionApprovalCapabilityPolicyRegistry:
    if not isinstance(policies, ActionApprovalCapabilityPolicyRegistry):
        raise TypeError(f"{label} requires the exact deployment policy registry")
    try:
        return ActionApprovalCapabilityPolicyRegistry(policies.policies())
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise TypeError(f"{label} policy registry is not canonical") from exc


def _approved_reversible_records_from_rows(
    approval_row: sqlite3.Row,
    permit_row: sqlite3.Row,
    receipt_row: sqlite3.Row,
    reservation_row: sqlite3.Row,
    *,
    campaign_id: str,
) -> tuple[
    ActionApprovalEnvelope,
    ActionPermit,
    ActionApprovalConsumptionReceipt,
    ActionCleanupReservation,
]:
    return (
        _action_approval_from_row(approval_row, campaign_id=campaign_id),
        _action_permit_from_row(permit_row, campaign_id=campaign_id),
        _approval_consumption_from_row(receipt_row, campaign_id=campaign_id),
        _cleanup_reservation_from_row(reservation_row, campaign_id=campaign_id),
    )


def _approved_reversible_authorization(
    approval: ActionApprovalEnvelope,
    permit: ActionPermit,
    receipt: ActionApprovalConsumptionReceipt,
    reservation: ActionCleanupReservation,
    *,
    newly_consumed: bool,
) -> ApprovedReversibleActionPermitAuthorization:
    return ApprovedReversibleActionPermitAuthorization(
        approval=approval,
        reversible=ReversibleActionPermitAuthorization(
            action=ActionPermitAuthorization(
                permit=permit,
                newlyConsumed=newly_consumed,
            ),
            cleanupReservation=reservation,
        ),
        receipt=receipt,
    )


def _approved_reversible_transaction_rows(
    connection: sqlite3.Connection,
    *,
    approval_id: str,
    permit_id: str,
) -> tuple[
    sqlite3.Row | None,
    sqlite3.Row | None,
    sqlite3.Row | None,
    sqlite3.Row | None,
]:
    approval_row = connection.execute(
        """
        SELECT * FROM graph_action_approval_envelopes
        WHERE approval_id = ?
        """,
        (approval_id,),
    ).fetchone()
    permit_row = connection.execute(
        "SELECT * FROM graph_action_permits WHERE permit_id = ?",
        (permit_id,),
    ).fetchone()
    receipt_row = connection.execute(
        """
        SELECT * FROM graph_action_approval_consumptions
        WHERE permit_id = ?
        """,
        (permit_id,),
    ).fetchone()
    reservation_row = connection.execute(
        """
        SELECT * FROM graph_action_cleanup_reservations
        WHERE source_action_permit_id = ?
        """,
        (permit_id,),
    ).fetchone()
    return approval_row, permit_row, receipt_row, reservation_row


def _approved_reversible_identity_is_consumed(
    connection: sqlite3.Connection,
    *,
    approval: ActionApprovalEnvelope,
    proposal: ActionProposal,
    cleanup_request: ActionCleanupReservationRequest,
) -> bool:
    collision = connection.execute(
        """
        SELECT 1 FROM graph_action_approval_envelopes
        WHERE proposal_id = ? OR request_id = ?
        UNION ALL
        SELECT 1 FROM graph_action_approval_consumptions
        WHERE approval_id = ? OR proposal_id = ? OR request_id = ?
        UNION ALL
        SELECT 1 FROM graph_action_permits
        WHERE proposal_id = ? OR request_id = ?
        UNION ALL
        SELECT 1 FROM graph_cleanup_permits WHERE request_id = ?
        LIMIT 1
        """,
        (
            proposal.proposal_id,
            proposal.request_id,
            approval.approval_id,
            proposal.proposal_id,
            proposal.request_id,
            proposal.proposal_id,
            proposal.request_id,
            proposal.request_id,
        ),
    ).fetchone()
    reservation_collision = connection.execute(
        """
        SELECT 1 FROM graph_action_cleanup_reservations
        WHERE reservation_request_id = ?
        LIMIT 1
        """,
        (cleanup_request.reservation_request_id,),
    ).fetchone()
    return collision is not None or reservation_collision is not None


GRAPH_STORE_BACKUP_MANIFEST_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-backup-manifest/v1alpha3"
] = "pajin.dev/sqlite-graph-backup-manifest/v1alpha3"
_CLEANUP_GRAPH_STORE_BACKUP_MANIFEST_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-backup-manifest/v1alpha2"
] = "pajin.dev/sqlite-graph-backup-manifest/v1alpha2"
_LEGACY_GRAPH_STORE_BACKUP_MANIFEST_API_VERSION: Literal[
    "pajin.dev/sqlite-graph-backup-manifest/v1alpha1"
] = "pajin.dev/sqlite-graph-backup-manifest/v1alpha1"
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_LEGACY_TABLES = frozenset(
    {
        "graph_store_metadata",
        "graph_store_writers",
        "graph_events",
        "graph_nodes",
        "graph_projections",
        "graph_snapshots",
    }
)

_METADATA_TABLE_SQL = """
    CREATE TABLE graph_store_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    ) STRICT
    """
_WRITERS_TABLE_SQL = """
    CREATE TABLE graph_store_writers (
        writer_kind TEXT PRIMARY KEY NOT NULL
            CHECK (writer_kind IN ('event', 'snapshot')),
        writer_id TEXT NOT NULL,
        writer_digest TEXT NOT NULL CHECK (length(writer_digest) = 64)
    ) STRICT
    """
_EVENTS_TABLE_SQL = """
    CREATE TABLE graph_events (
        sequence INTEGER PRIMARY KEY NOT NULL CHECK (sequence >= 1),
        event_id TEXT NOT NULL UNIQUE,
        event_digest TEXT NOT NULL UNIQUE CHECK (length(event_digest) = 64),
        previous_event_digest TEXT CHECK (
            previous_event_digest IS NULL OR length(previous_event_digest) = 64
        ),
        proposal_id TEXT NOT NULL,
        proposal_digest TEXT NOT NULL CHECK (length(proposal_digest) = 64),
        decision TEXT NOT NULL CHECK (decision IN ('admitted', 'rejected')),
        event_json BLOB NOT NULL,
        UNIQUE (proposal_id, proposal_digest)
    ) STRICT
    """
_EVENTS_PROPOSAL_INDEX_SQL = (
    "CREATE INDEX graph_events_proposal_idx ON graph_events(proposal_id, sequence)"
)
_NODES_TABLE_SQL = """
    CREATE TABLE graph_nodes (
        node_id TEXT PRIMARY KEY NOT NULL,
        node_kind TEXT NOT NULL,
        admitted_sequence INTEGER NOT NULL REFERENCES graph_events(sequence),
        node_json BLOB NOT NULL
    ) STRICT
    """
_PROJECTIONS_TABLE_SQL = """
    CREATE TABLE graph_projections (
        revision INTEGER PRIMARY KEY NOT NULL CHECK (revision >= 0),
        event_log_head_digest TEXT CHECK (
            event_log_head_digest IS NULL OR length(event_log_head_digest) = 64
        ),
        projection_id TEXT NOT NULL UNIQUE,
        projection_digest TEXT NOT NULL UNIQUE CHECK (length(projection_digest) = 64),
        projection_json BLOB NOT NULL,
        CHECK (
            (revision = 0 AND event_log_head_digest IS NULL)
            OR (revision > 0 AND event_log_head_digest IS NOT NULL)
        )
    ) STRICT
    """
_SNAPSHOTS_TABLE_SQL = """
    CREATE TABLE graph_snapshots (
        ordinal INTEGER PRIMARY KEY NOT NULL CHECK (ordinal >= 1),
        snapshot_id TEXT NOT NULL UNIQUE,
        snapshot_digest TEXT NOT NULL UNIQUE CHECK (length(snapshot_digest) = 64),
        previous_snapshot_digest TEXT CHECK (
            previous_snapshot_digest IS NULL OR length(previous_snapshot_digest) = 64
        ),
        revision INTEGER NOT NULL REFERENCES graph_projections(revision),
        projection_digest TEXT NOT NULL CHECK (length(projection_digest) = 64),
        snapshot_json BLOB NOT NULL
    ) STRICT
    """
_ACTION_PERMIT_WRITERS_TABLE_SQL = """
    CREATE TABLE graph_action_permit_writers (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
        compiler_id TEXT NOT NULL,
        compiler_version TEXT NOT NULL,
        compiler_digest TEXT NOT NULL CHECK (length(compiler_digest) = 64)
    ) STRICT
    """
_ACTION_PERMITS_TABLE_SQL = """
    CREATE TABLE graph_action_permits (
        ordinal INTEGER PRIMARY KEY NOT NULL CHECK (ordinal >= 1),
        permit_id TEXT NOT NULL UNIQUE,
        permit_digest TEXT NOT NULL UNIQUE CHECK (length(permit_digest) = 64),
        dispatch_id TEXT NOT NULL UNIQUE,
        envelope_id TEXT NOT NULL,
        envelope_digest TEXT NOT NULL CHECK (length(envelope_digest) = 64),
        proposal_id TEXT NOT NULL UNIQUE,
        proposal_digest TEXT NOT NULL CHECK (length(proposal_digest) = 64),
        decision_id TEXT NOT NULL,
        decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 64),
        snapshot_id TEXT NOT NULL REFERENCES graph_snapshots(snapshot_id),
        snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
        revision INTEGER NOT NULL REFERENCES graph_projections(revision),
        event_log_head_digest TEXT CHECK (
            event_log_head_digest IS NULL OR length(event_log_head_digest) = 64
        ),
        projection_digest TEXT NOT NULL CHECK (length(projection_digest) = 64),
        request_id TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
        request_units INTEGER NOT NULL CHECK (request_units >= 1),
        cost_microusd INTEGER NOT NULL CHECK (cost_microusd >= 0),
        issued_at TEXT NOT NULL,
        consumed_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        permit_json BLOB NOT NULL,
        CHECK (
            (revision = 0 AND event_log_head_digest IS NULL)
            OR (revision > 0 AND event_log_head_digest IS NOT NULL)
        )
    ) STRICT
    """
_ACTION_PERMITS_ENVELOPE_INDEX_SQL = (
    "CREATE INDEX graph_action_permits_envelope_idx ON graph_action_permits(envelope_id, ordinal)"
)
_ACTION_CLEANUP_RESERVATIONS_TABLE_SQL = """
    CREATE TABLE graph_action_cleanup_reservations (
        ordinal INTEGER PRIMARY KEY NOT NULL CHECK (ordinal >= 1),
        cleanup_reservation_id TEXT NOT NULL UNIQUE,
        cleanup_reservation_digest TEXT NOT NULL UNIQUE
            CHECK (length(cleanup_reservation_digest) = 64),
        reservation_request_id TEXT NOT NULL UNIQUE,
        reservation_request_digest TEXT NOT NULL
            CHECK (length(reservation_request_digest) = 64),
        source_action_permit_id TEXT NOT NULL UNIQUE
            REFERENCES graph_action_permits(permit_id),
        source_action_permit_digest TEXT NOT NULL
            CHECK (length(source_action_permit_digest) = 64),
        source_action_dispatch_id TEXT NOT NULL UNIQUE,
        envelope_id TEXT NOT NULL,
        envelope_digest TEXT NOT NULL CHECK (length(envelope_digest) = 64),
        cleanup_capability_digest TEXT NOT NULL
            CHECK (length(cleanup_capability_digest) = 64),
        target_digest TEXT NOT NULL CHECK (length(target_digest) = 64),
        cleanup_handler_digest TEXT NOT NULL CHECK (length(cleanup_handler_digest) = 64),
        cleanup_executor_digest TEXT NOT NULL CHECK (length(cleanup_executor_digest) = 64),
        tool_calls INTEGER NOT NULL CHECK (tool_calls = 1),
        request_units INTEGER NOT NULL CHECK (request_units >= 1),
        cost_microusd INTEGER NOT NULL CHECK (cost_microusd >= 0),
        reserved_at TEXT NOT NULL,
        claim_expires_at TEXT NOT NULL,
        reservation_json BLOB NOT NULL
    ) STRICT
    """
_ACTION_CLEANUP_RESERVATIONS_ENVELOPE_INDEX_SQL = (
    "CREATE INDEX graph_action_cleanup_reservations_envelope_idx "
    "ON graph_action_cleanup_reservations(envelope_id, ordinal)"
)
_CLEANUP_PERMITS_TABLE_SQL = """
    CREATE TABLE graph_cleanup_permits (
        ordinal INTEGER PRIMARY KEY NOT NULL CHECK (ordinal >= 1),
        cleanup_permit_id TEXT NOT NULL UNIQUE,
        cleanup_permit_digest TEXT NOT NULL UNIQUE
            CHECK (length(cleanup_permit_digest) = 64),
        cleanup_dispatch_id TEXT NOT NULL UNIQUE,
        cleanup_reservation_id TEXT NOT NULL UNIQUE
            REFERENCES graph_action_cleanup_reservations(cleanup_reservation_id),
        cleanup_reservation_digest TEXT NOT NULL
            CHECK (length(cleanup_reservation_digest) = 64),
        source_action_permit_id TEXT NOT NULL UNIQUE
            REFERENCES graph_action_permits(permit_id),
        source_action_permit_digest TEXT NOT NULL
            CHECK (length(source_action_permit_digest) = 64),
        envelope_id TEXT NOT NULL,
        envelope_digest TEXT NOT NULL CHECK (length(envelope_digest) = 64),
        cleanup_request_id TEXT NOT NULL UNIQUE,
        cleanup_request_digest TEXT NOT NULL CHECK (length(cleanup_request_digest) = 64),
        decision_id TEXT NOT NULL,
        decision_digest TEXT NOT NULL CHECK (length(decision_digest) = 64),
        snapshot_id TEXT NOT NULL REFERENCES graph_snapshots(snapshot_id),
        snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
        revision INTEGER NOT NULL REFERENCES graph_projections(revision),
        event_log_head_digest TEXT CHECK (
            event_log_head_digest IS NULL OR length(event_log_head_digest) = 64
        ),
        projection_digest TEXT NOT NULL CHECK (length(projection_digest) = 64),
        request_id TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
        cleanup_capability_digest TEXT NOT NULL
            CHECK (length(cleanup_capability_digest) = 64),
        target_digest TEXT NOT NULL CHECK (length(target_digest) = 64),
        cleanup_handler_digest TEXT NOT NULL CHECK (length(cleanup_handler_digest) = 64),
        cleanup_executor_digest TEXT NOT NULL CHECK (length(cleanup_executor_digest) = 64),
        cleanup_plan_digest TEXT NOT NULL CHECK (length(cleanup_plan_digest) = 64),
        issued_at TEXT NOT NULL,
        consumed_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        permit_json BLOB NOT NULL,
        CHECK (
            (revision = 0 AND event_log_head_digest IS NULL)
            OR (revision > 0 AND event_log_head_digest IS NOT NULL)
        )
    ) STRICT
    """
_CLEANUP_PERMITS_ENVELOPE_INDEX_SQL = (
    "CREATE INDEX graph_cleanup_permits_envelope_idx "
    "ON graph_cleanup_permits(envelope_id, ordinal)"
)
_ACTION_APPROVAL_ENVELOPES_TABLE_SQL = """
    CREATE TABLE graph_action_approval_envelopes (
        ordinal INTEGER PRIMARY KEY NOT NULL CHECK (ordinal >= 1),
        approval_id TEXT NOT NULL UNIQUE,
        approval_digest TEXT NOT NULL UNIQUE CHECK (length(approval_digest) = 64),
        campaign_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        envelope_id TEXT NOT NULL,
        envelope_digest TEXT NOT NULL CHECK (length(envelope_digest) = 64),
        issuer_authority_id TEXT NOT NULL,
        issuer_authority_digest TEXT NOT NULL
            CHECK (length(issuer_authority_digest) = 64),
        capability_id TEXT NOT NULL,
        capability_version TEXT NOT NULL,
        capability_digest TEXT NOT NULL CHECK (length(capability_digest) = 64),
        release_id TEXT NOT NULL,
        release_digest TEXT NOT NULL CHECK (length(release_digest) = 64),
        proposal_id TEXT NOT NULL UNIQUE,
        proposal_digest TEXT NOT NULL CHECK (length(proposal_digest) = 64),
        target_digest TEXT NOT NULL CHECK (length(target_digest) = 64),
        request_id TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
        normalized_parameters_digest TEXT NOT NULL
            CHECK (length(normalized_parameters_digest) = 64),
        risk_tier TEXT NOT NULL CHECK (risk_tier IN ('T0', 'T1', 'T2')),
        request_units INTEGER NOT NULL CHECK (request_units >= 1),
        cost_microusd INTEGER NOT NULL CHECK (cost_microusd >= 0),
        approved_at TEXT NOT NULL,
        not_before TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        approval_json BLOB NOT NULL
    ) STRICT
    """
_ACTION_APPROVAL_ENVELOPES_ENVELOPE_INDEX_SQL = (
    "CREATE INDEX graph_action_approval_envelopes_envelope_idx "
    "ON graph_action_approval_envelopes(envelope_id, ordinal)"
)
_ACTION_APPROVAL_CONSUMPTIONS_TABLE_SQL = """
    CREATE TABLE graph_action_approval_consumptions (
        ordinal INTEGER PRIMARY KEY NOT NULL CHECK (ordinal >= 1),
        receipt_id TEXT NOT NULL UNIQUE,
        receipt_digest TEXT NOT NULL UNIQUE CHECK (length(receipt_digest) = 64),
        approval_id TEXT NOT NULL UNIQUE
            REFERENCES graph_action_approval_envelopes(approval_id),
        approval_digest TEXT NOT NULL CHECK (length(approval_digest) = 64),
        permit_id TEXT NOT NULL UNIQUE REFERENCES graph_action_permits(permit_id),
        permit_digest TEXT NOT NULL CHECK (length(permit_digest) = 64),
        dispatch_id TEXT NOT NULL UNIQUE,
        proposal_id TEXT NOT NULL UNIQUE,
        proposal_digest TEXT NOT NULL CHECK (length(proposal_digest) = 64),
        request_id TEXT NOT NULL UNIQUE,
        request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
        normalized_parameters_digest TEXT NOT NULL
            CHECK (length(normalized_parameters_digest) = 64),
        consumed_at TEXT NOT NULL,
        receipt_json BLOB NOT NULL
    ) STRICT
    """
_ACTION_APPROVAL_CONSUMPTIONS_ENVELOPE_INDEX_SQL = (
    "CREATE INDEX graph_action_approval_consumptions_approval_idx "
    "ON graph_action_approval_consumptions(approval_id, ordinal)"
)


def _immutable_triggers(table: str, identity_column: str) -> dict[tuple[str, str], str]:
    return {
        (
            "trigger",
            f"{table}_no_update",
        ): f"""
            CREATE TRIGGER {table}_no_update
            BEFORE UPDATE ON {table}
            BEGIN
                SELECT RAISE(ABORT, '{table} is append-only');
            END
        """,
        (
            "trigger",
            f"{table}_no_delete",
        ): f"""
            CREATE TRIGGER {table}_no_delete
            BEFORE DELETE ON {table}
            BEGIN
                SELECT RAISE(ABORT, '{table} is append-only');
            END
        """,
        (
            "trigger",
            f"{table}_no_replace",
        ): f"""
            CREATE TRIGGER {table}_no_replace
            BEFORE INSERT ON {table}
            WHEN EXISTS (
                SELECT 1 FROM {table}
                WHERE {identity_column} = NEW.{identity_column}
            )
            BEGIN
                SELECT RAISE(ABORT, '{table} cannot be replaced');
            END
        """,
    }


_LEGACY_SCHEMA_OBJECT_SQL: dict[tuple[str, str], str] = {
    ("table", "graph_store_metadata"): _METADATA_TABLE_SQL,
    ("table", "graph_store_writers"): _WRITERS_TABLE_SQL,
    ("table", "graph_events"): _EVENTS_TABLE_SQL,
    ("index", "graph_events_proposal_idx"): _EVENTS_PROPOSAL_INDEX_SQL,
    ("table", "graph_nodes"): _NODES_TABLE_SQL,
    ("table", "graph_projections"): _PROJECTIONS_TABLE_SQL,
    ("table", "graph_snapshots"): _SNAPSHOTS_TABLE_SQL,
}
for _table, _identity in (
    ("graph_store_metadata", "key"),
    ("graph_store_writers", "writer_kind"),
    ("graph_events", "sequence"),
    ("graph_nodes", "node_id"),
    ("graph_projections", "revision"),
    ("graph_snapshots", "ordinal"),
):
    _LEGACY_SCHEMA_OBJECT_SQL.update(_immutable_triggers(_table, _identity))

_ACTION_PERMIT_SCHEMA_OBJECT_SQL = dict(_LEGACY_SCHEMA_OBJECT_SQL)
_ACTION_PERMIT_SCHEMA_OBJECT_SQL.update(
    {
        ("table", "graph_action_permit_writers"): _ACTION_PERMIT_WRITERS_TABLE_SQL,
        ("table", "graph_action_permits"): _ACTION_PERMITS_TABLE_SQL,
        (
            "index",
            "graph_action_permits_envelope_idx",
        ): _ACTION_PERMITS_ENVELOPE_INDEX_SQL,
    }
)
for _table, _identity in (
    ("graph_action_permit_writers", "singleton"),
    ("graph_action_permits", "ordinal"),
):
    _ACTION_PERMIT_SCHEMA_OBJECT_SQL.update(_immutable_triggers(_table, _identity))

_ACTION_PERMIT_TABLES = _LEGACY_TABLES | {
    "graph_action_permit_writers",
    "graph_action_permits",
}

_CLEANUP_SCHEMA_OBJECT_SQL = dict(_ACTION_PERMIT_SCHEMA_OBJECT_SQL)
_CLEANUP_SCHEMA_OBJECT_SQL.update(
    {
        (
            "table",
            "graph_action_cleanup_reservations",
        ): _ACTION_CLEANUP_RESERVATIONS_TABLE_SQL,
        (
            "index",
            "graph_action_cleanup_reservations_envelope_idx",
        ): _ACTION_CLEANUP_RESERVATIONS_ENVELOPE_INDEX_SQL,
        ("table", "graph_cleanup_permits"): _CLEANUP_PERMITS_TABLE_SQL,
        (
            "index",
            "graph_cleanup_permits_envelope_idx",
        ): _CLEANUP_PERMITS_ENVELOPE_INDEX_SQL,
    }
)
for _table, _identity in (
    ("graph_action_cleanup_reservations", "ordinal"),
    ("graph_cleanup_permits", "ordinal"),
):
    _CLEANUP_SCHEMA_OBJECT_SQL.update(_immutable_triggers(_table, _identity))

_CLEANUP_TABLES = _ACTION_PERMIT_TABLES | {
    "graph_action_cleanup_reservations",
    "graph_cleanup_permits",
}

_SCHEMA_OBJECT_SQL = dict(_CLEANUP_SCHEMA_OBJECT_SQL)
_SCHEMA_OBJECT_SQL.update(
    {
        (
            "table",
            "graph_action_approval_envelopes",
        ): _ACTION_APPROVAL_ENVELOPES_TABLE_SQL,
        (
            "index",
            "graph_action_approval_envelopes_envelope_idx",
        ): _ACTION_APPROVAL_ENVELOPES_ENVELOPE_INDEX_SQL,
        (
            "table",
            "graph_action_approval_consumptions",
        ): _ACTION_APPROVAL_CONSUMPTIONS_TABLE_SQL,
        (
            "index",
            "graph_action_approval_consumptions_approval_idx",
        ): _ACTION_APPROVAL_CONSUMPTIONS_ENVELOPE_INDEX_SQL,
    }
)
for _table, _identity in (
    ("graph_action_approval_envelopes", "ordinal"),
    ("graph_action_approval_consumptions", "ordinal"),
):
    _SCHEMA_OBJECT_SQL.update(_immutable_triggers(_table, _identity))

_TABLES = _CLEANUP_TABLES | {
    "graph_action_approval_envelopes",
    "graph_action_approval_consumptions",
}


def _normalize_schema_sql(value: str) -> str:
    return " ".join(value.split())


def _schema_digest(objects: dict[tuple[str, str], str]) -> str:
    return sha256(
        json.dumps(
            {
                f"{object_type}:{name}": _normalize_schema_sql(statement)
                for (object_type, name), statement in sorted(objects.items())
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


_LEGACY_SCHEMA_DIGEST = _schema_digest(_LEGACY_SCHEMA_OBJECT_SQL)
_ACTION_PERMIT_SCHEMA_DIGEST = _schema_digest(_ACTION_PERMIT_SCHEMA_OBJECT_SQL)
_CLEANUP_SCHEMA_DIGEST = _schema_digest(_CLEANUP_SCHEMA_OBJECT_SQL)
_SCHEMA_DIGEST = _schema_digest(_SCHEMA_OBJECT_SQL)


class SQLiteGraphStoreError(RuntimeError):
    """Raised when the durable Graph Store cannot establish a trusted boundary."""


class _SQLiteGraphBackupManifestV1(StrictModel):
    """Legacy v2 database manifest retained solely for verified restore."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/sqlite-graph-backup-manifest/v1alpha1"] = Field(
        default=_LEGACY_GRAPH_STORE_BACKUP_MANIFEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphBackupManifest"] = "SQLiteGraphBackupManifest"
    backup_id: str = Field(default="", alias="backupId", max_length=96)
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    schema_version: Literal[2] = Field(default=2, alias="schemaVersion")
    schema_digest: _Sha256 = Field(
        default=_ACTION_PERMIT_SCHEMA_DIGEST,
        alias="schemaDigest",
    )
    created_at: datetime = Field(alias="createdAt")
    database_sha256: _Sha256 = Field(alias="databaseSha256")
    database_bytes: int = Field(alias="databaseBytes", ge=1, le=_MAX_GRAPH_BACKUP_BYTES)
    event_count: int = Field(alias="eventCount", ge=0)
    event_log_head_digest: _Sha256 | None = Field(alias="eventLogHeadDigest")
    projection_revision: int = Field(alias="projectionRevision", ge=0)
    projection_digest: _Sha256 = Field(alias="projectionDigest")
    snapshot_count: int = Field(alias="snapshotCount", ge=0)
    snapshot_head_digest: _Sha256 | None = Field(alias="snapshotHeadDigest")
    action_permit_count: int = Field(alias="actionPermitCount", ge=0)
    action_permit_head_digest: _Sha256 | None = Field(alias="actionPermitHeadDigest")

    @field_validator("created_at")
    @classmethod
    def require_utc_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("SQLite Graph backup creation time must be UTC")
        return value

    @model_validator(mode="after")
    def bind_backup_identity(self) -> Self:
        if self.schema_digest != _ACTION_PERMIT_SCHEMA_DIGEST:
            raise ValueError("legacy SQLite Graph backup schema digest differs")
        if (self.event_count == 0) is not (self.event_log_head_digest is None):
            raise ValueError("SQLite Graph backup Event count and head are inconsistent")
        if self.projection_revision > self.event_count:
            raise ValueError("SQLite Graph backup Projection is ahead of its Event Log")
        if (self.snapshot_count == 0) is not (self.snapshot_head_digest is None):
            raise ValueError("SQLite Graph backup Snapshot count and head are inconsistent")
        if (self.action_permit_count == 0) is not (
            self.action_permit_head_digest is None
        ):
            raise ValueError("SQLite Graph backup Permit count and head are inconsistent")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"backup_id"},
        )
        digest = sha256(
            canonical_graph_json(
                material,
                label="SQLiteGraphBackupManifest",
                max_bytes=_MAX_GRAPH_BACKUP_MANIFEST_BYTES,
            )
        ).hexdigest()
        backup_id = f"graph-store-backup_{digest}"
        if self.backup_id and self.backup_id != backup_id:
            raise ValueError("SQLite Graph backup ID differs from canonical material")
        object.__setattr__(self, "backup_id", backup_id)
        return self


class _SQLiteGraphBackupManifestV2(StrictModel):
    """Legacy v3 cleanup database manifest retained solely for verified restore."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/sqlite-graph-backup-manifest/v1alpha2"] = Field(
        default=_CLEANUP_GRAPH_STORE_BACKUP_MANIFEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphBackupManifest"] = "SQLiteGraphBackupManifest"
    backup_id: str = Field(default="", alias="backupId", max_length=96)
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    schema_version: Literal[3] = Field(default=3, alias="schemaVersion")
    schema_digest: _Sha256 = Field(default=_CLEANUP_SCHEMA_DIGEST, alias="schemaDigest")
    created_at: datetime = Field(alias="createdAt")
    database_sha256: _Sha256 = Field(alias="databaseSha256")
    database_bytes: int = Field(alias="databaseBytes", ge=1, le=_MAX_GRAPH_BACKUP_BYTES)
    event_count: int = Field(alias="eventCount", ge=0)
    event_log_head_digest: _Sha256 | None = Field(alias="eventLogHeadDigest")
    projection_revision: int = Field(alias="projectionRevision", ge=0)
    projection_digest: _Sha256 = Field(alias="projectionDigest")
    snapshot_count: int = Field(alias="snapshotCount", ge=0)
    snapshot_head_digest: _Sha256 | None = Field(alias="snapshotHeadDigest")
    action_permit_count: int = Field(alias="actionPermitCount", ge=0)
    action_permit_head_digest: _Sha256 | None = Field(alias="actionPermitHeadDigest")
    cleanup_reservation_count: int = Field(alias="cleanupReservationCount", ge=0)
    cleanup_reservation_head_digest: _Sha256 | None = Field(
        alias="cleanupReservationHeadDigest"
    )
    cleanup_permit_count: int = Field(alias="cleanupPermitCount", ge=0)
    cleanup_permit_head_digest: _Sha256 | None = Field(alias="cleanupPermitHeadDigest")

    @field_validator("created_at")
    @classmethod
    def require_utc_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("SQLite Graph backup creation time must be UTC")
        return value

    @model_validator(mode="after")
    def bind_backup_identity(self) -> Self:
        if self.schema_digest != _CLEANUP_SCHEMA_DIGEST:
            raise ValueError("legacy cleanup SQLite Graph backup schema digest differs")
        if (self.event_count == 0) is not (self.event_log_head_digest is None):
            raise ValueError("SQLite Graph backup Event count and head are inconsistent")
        if self.projection_revision > self.event_count:
            raise ValueError("SQLite Graph backup Projection is ahead of its Event Log")
        if (self.snapshot_count == 0) is not (self.snapshot_head_digest is None):
            raise ValueError("SQLite Graph backup Snapshot count and head are inconsistent")
        if (self.action_permit_count == 0) is not (
            self.action_permit_head_digest is None
        ):
            raise ValueError("SQLite Graph backup Permit count and head are inconsistent")
        if (self.cleanup_reservation_count == 0) is not (
            self.cleanup_reservation_head_digest is None
        ):
            raise ValueError(
                "SQLite Graph backup cleanup reservation count and head are inconsistent"
            )
        if (self.cleanup_permit_count == 0) is not (
            self.cleanup_permit_head_digest is None
        ):
            raise ValueError(
                "SQLite Graph backup CleanupPermit count and head are inconsistent"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"backup_id"},
        )
        digest = sha256(
            canonical_graph_json(
                material,
                label="SQLiteGraphBackupManifest",
                max_bytes=_MAX_GRAPH_BACKUP_MANIFEST_BYTES,
            )
        ).hexdigest()
        backup_id = f"graph-store-backup_{digest}"
        if self.backup_id and self.backup_id != backup_id:
            raise ValueError("SQLite Graph backup ID differs from canonical material")
        object.__setattr__(self, "backup_id", backup_id)
        return self


class SQLiteGraphBackupManifest(StrictModel):
    """Content-addressed identity and logical-state summary for one Graph backup."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/sqlite-graph-backup-manifest/v1alpha3"] = Field(
        default=GRAPH_STORE_BACKUP_MANIFEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SQLiteGraphBackupManifest"] = "SQLiteGraphBackupManifest"
    backup_id: str = Field(default="", alias="backupId", max_length=96)
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    schema_version: Literal[4] = Field(default=4, alias="schemaVersion")
    schema_digest: _Sha256 = Field(default=_SCHEMA_DIGEST, alias="schemaDigest")
    created_at: datetime = Field(alias="createdAt")
    database_sha256: _Sha256 = Field(alias="databaseSha256")
    database_bytes: int = Field(alias="databaseBytes", ge=1, le=_MAX_GRAPH_BACKUP_BYTES)
    event_count: int = Field(alias="eventCount", ge=0)
    event_log_head_digest: _Sha256 | None = Field(alias="eventLogHeadDigest")
    projection_revision: int = Field(alias="projectionRevision", ge=0)
    projection_digest: _Sha256 = Field(alias="projectionDigest")
    snapshot_count: int = Field(alias="snapshotCount", ge=0)
    snapshot_head_digest: _Sha256 | None = Field(alias="snapshotHeadDigest")
    action_permit_count: int = Field(alias="actionPermitCount", ge=0)
    action_permit_head_digest: _Sha256 | None = Field(alias="actionPermitHeadDigest")
    cleanup_reservation_count: int = Field(alias="cleanupReservationCount", ge=0)
    cleanup_reservation_head_digest: _Sha256 | None = Field(alias="cleanupReservationHeadDigest")
    cleanup_permit_count: int = Field(alias="cleanupPermitCount", ge=0)
    cleanup_permit_head_digest: _Sha256 | None = Field(alias="cleanupPermitHeadDigest")
    action_approval_count: int = Field(default=0, alias="actionApprovalCount", ge=0)
    action_approval_head_digest: _Sha256 | None = Field(
        default=None,
        alias="actionApprovalHeadDigest",
    )
    approval_consumption_count: int = Field(
        default=0,
        alias="approvalConsumptionCount",
        ge=0,
    )
    approval_consumption_head_digest: _Sha256 | None = Field(
        default=None,
        alias="approvalConsumptionHeadDigest",
    )

    @field_validator("created_at")
    @classmethod
    def require_utc_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("SQLite Graph backup creation time must be UTC")
        return value

    @model_validator(mode="after")
    def bind_backup_identity(self) -> Self:
        if self.schema_digest != _SCHEMA_DIGEST:
            raise ValueError("SQLite Graph backup schema digest differs")
        if (self.event_count == 0) is not (self.event_log_head_digest is None):
            raise ValueError("SQLite Graph backup Event count and head are inconsistent")
        if self.projection_revision > self.event_count:
            raise ValueError("SQLite Graph backup Projection is ahead of its Event Log")
        for count, head, label in (
            (self.snapshot_count, self.snapshot_head_digest, "Snapshot"),
            (self.action_permit_count, self.action_permit_head_digest, "Permit"),
            (
                self.cleanup_reservation_count,
                self.cleanup_reservation_head_digest,
                "cleanup reservation",
            ),
            (self.cleanup_permit_count, self.cleanup_permit_head_digest, "CleanupPermit"),
            (self.action_approval_count, self.action_approval_head_digest, "approval"),
            (
                self.approval_consumption_count,
                self.approval_consumption_head_digest,
                "approval consumption",
            ),
        ):
            if (count == 0) is not (head is None):
                raise ValueError(f"SQLite Graph backup {label} count and head are inconsistent")
        if self.action_approval_count != self.approval_consumption_count:
            raise ValueError("SQLite Graph backup approval and consumption counts are inconsistent")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"backup_id"},
        )
        digest = sha256(
            canonical_graph_json(
                material,
                label="SQLiteGraphBackupManifest",
                max_bytes=_MAX_GRAPH_BACKUP_MANIFEST_BYTES,
            )
        ).hexdigest()
        backup_id = f"graph-store-backup_{digest}"
        if self.backup_id and self.backup_id != backup_id:
            raise ValueError("SQLite Graph backup ID differs from canonical material")
        object.__setattr__(self, "backup_id", backup_id)
        return self


@dataclass(frozen=True, slots=True)
class _VerifiedGraphStoreState:
    event_count: int
    event_log_head_digest: str | None
    projection_revision: int
    projection_digest: str
    snapshot_count: int
    snapshot_head_digest: str | None
    action_permit_count: int
    action_permit_head_digest: str | None
    cleanup_reservation_count: int
    cleanup_reservation_head_digest: str | None
    cleanup_permit_count: int
    cleanup_permit_head_digest: str | None
    action_approval_count: int
    action_approval_head_digest: str | None
    approval_consumption_count: int
    approval_consumption_head_digest: str | None


class SQLiteGraphStore:
    """Own one Campaign's durable Graph and final ActionPermit authority."""

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        if fullmatch(r"^[a-z0-9][a-z0-9-]{2,79}$", campaign_id) is None:
            raise ValueError("SQLite Graph Store campaign ID is invalid")
        self.path = _absolute_path(path)
        self.campaign_id = campaign_id
        _initialize(self.path, campaign_id)
        self.event_log = SQLiteGraphEventLog(self.path, campaign_id=campaign_id)
        self.projection_store = SQLiteGraphProjectionStore(
            self.path,
            campaign_id=campaign_id,
        )
        self.snapshot_store = SQLiteGraphSnapshotStore(
            self.path,
            campaign_id=campaign_id,
        )
        self.permit_store = SQLiteGraphActionPermitStore(
            self.path,
            campaign_id=campaign_id,
        )
        self.approved_permit_store = self.permit_store

    def create_backup(
        self,
        destination: Path,
        *,
        created_at: datetime | None = None,
    ) -> SQLiteGraphBackupManifest:
        """Create one consistent, verified database plus content-addressed manifest."""

        return _create_backup(
            self.path,
            destination,
            campaign_id=self.campaign_id,
            created_at=created_at or datetime.now(UTC),
        )

    def create_retained_backup(
        self,
        destination: Path,
        *,
        encryption_key_id: str,
        encryption_key: bytes,
        signer: SQLiteGraphBackupSigner,
        created_at: datetime | None = None,
    ) -> SQLiteGraphRetainedBackupManifest:
        """Create one encrypted and externally signed retention object."""

        from pajin.graph.backup_retention import (
            create_retained_sqlite_graph_backup,
        )

        return create_retained_sqlite_graph_backup(
            self,
            destination,
            encryption_key_id=encryption_key_id,
            encryption_key=encryption_key,
            signer=signer,
            created_at=created_at,
        )

    @classmethod
    def restore_backup(
        cls,
        backup: Path,
        *,
        destination: Path,
        campaign_id: str,
    ) -> SQLiteGraphStore:
        """Verify a backup and restore it only to a previously absent database path."""

        _restore_backup(
            backup,
            destination=destination,
            campaign_id=campaign_id,
        )
        return cls(destination, campaign_id=campaign_id)

    @classmethod
    def restore_retained_backup(
        cls,
        retained_backup: Path,
        *,
        destination: Path,
        campaign_id: str,
        encryption_key_id: str,
        encryption_key: bytes,
        trusted_signing_keys: Iterable[SQLiteGraphBackupVerificationKey],
    ) -> SQLiteGraphStore:
        """Verify and decrypt a retained backup only into a new database path."""

        from pajin.graph.backup_retention import (
            restore_retained_sqlite_graph_backup,
        )

        return restore_retained_sqlite_graph_backup(
            retained_backup,
            destination=destination,
            campaign_id=campaign_id,
            encryption_key_id=encryption_key_id,
            encryption_key=encryption_key,
            trusted_signing_keys=trusted_signing_keys,
        )


class SQLiteGraphEventLog:
    """SQLite-backed append-only Graph Event Log with a pinned writer identity."""

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        self.path = _absolute_path(path)
        self._campaign_id = campaign_id
        self._writer: object | None = None
        self._writer_identity: tuple[str, str] | None = None
        self._lock = threading.RLock()

    def claim_writer(self, authority_id: str, authority_digest: str) -> object:
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", authority_id) is None
            or fullmatch(r"^[a-f0-9]{64}$", authority_digest) is None
        ):
            raise GraphEventLogError("Canonical Event Log writer identity is invalid")
        with self._lock:
            if self._writer is not None:
                raise GraphEventLogError("Canonical Event Log writer is already claimed")
            try:
                with _write_transaction(self.path) as connection:
                    _pin_writer(
                        connection,
                        writer_kind="event",
                        writer_id=authority_id,
                        writer_digest=authority_digest,
                    )
            except sqlite3.Error as exc:
                raise GraphEventLogError("Graph Event Log writer claim failed") from exc
            writer = object()
            self._writer = writer
            self._writer_identity = (authority_id, authority_digest)
            return writer

    def event_for_attempt(
        self,
        proposal_id: str,
        proposal_digest: str,
    ) -> GraphAdmissionEvent | None:
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    """
                    SELECT * FROM graph_events
                    WHERE proposal_id = ? AND proposal_digest = ?
                    """,
                    (proposal_id, proposal_digest),
                ).fetchone()
                return _event_from_row(row, campaign_id=self._campaign_id) if row else None
        except sqlite3.Error as exc:
            raise GraphEventLogError("Graph Event Log attempt lookup failed") from exc

    def first_proposal_digest(self, proposal_id: str) -> str | None:
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    """
                    SELECT proposal_digest FROM graph_events
                    WHERE proposal_id = ?
                    ORDER BY sequence
                    LIMIT 1
                    """,
                    (proposal_id,),
                ).fetchone()
                return cast(str, row["proposal_digest"]) if row else None
        except sqlite3.Error as exc:
            raise GraphEventLogError("Graph Event Log proposal lookup failed") from exc

    def next_position(self) -> tuple[int, str | None]:
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    """
                    SELECT sequence, event_digest FROM graph_events
                    ORDER BY sequence DESC
                    LIMIT 1
                    """
                ).fetchone()
                if row is None:
                    return 1, None
                return cast(int, row["sequence"]) + 1, cast(str, row["event_digest"])
        except sqlite3.Error as exc:
            raise GraphEventLogError("Graph Event Log head lookup failed") from exc

    def admitted_node(self, node_id: str) -> GraphNode | None:
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    "SELECT * FROM graph_nodes WHERE node_id = ?",
                    (node_id,),
                ).fetchone()
                return _node_from_row(row, campaign_id=self._campaign_id) if row else None
        except sqlite3.Error as exc:
            raise GraphEventLogError("Graph Event Log node lookup failed") from exc

    def append(
        self,
        event: GraphAdmissionEvent,
        *,
        writer: object,
    ) -> GraphAdmissionEvent:
        with self._lock:
            if writer is not self._writer or self._writer_identity is None:
                raise GraphEventLogError("Canonical Event Log write authority is invalid")
            stored = _canonical_event(event)
            if stored.campaign_id != self._campaign_id:
                raise GraphEventLogError("Graph event belongs to another Campaign")
            if self._writer_identity != (stored.authority_id, stored.authority_digest):
                raise GraphEventLogError("Graph event authority differs from the claimed writer")
            try:
                with _write_transaction(self.path) as connection:
                    if _writer_identity(connection, "event") != self._writer_identity:
                        raise GraphEventLogError(
                            "Graph event authority differs from durable writer identity"
                        )
                    self._require_next_event(connection, stored)
                    connection.execute(
                        """
                        INSERT INTO graph_events (
                            sequence, event_id, event_digest, previous_event_digest,
                            proposal_id, proposal_digest, decision, event_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            stored.sequence,
                            stored.event_id,
                            stored.event_digest,
                            stored.previous_event_digest,
                            stored.proposal_id,
                            stored.proposal_digest,
                            stored.decision.value,
                            sqlite3.Binary(_event_bytes(stored)),
                        ),
                    )
                    if stored.decision is GraphAdmissionDecision.ADMITTED:
                        self._record_nodes(connection, stored)
            except sqlite3.IntegrityError as exc:
                raise GraphEventLogError("Graph event append conflicted") from exc
            except sqlite3.Error as exc:
                raise GraphEventLogError("Graph event append failed") from exc
            return _canonical_event(stored)

    def events(self) -> tuple[GraphAdmissionEvent, ...]:
        try:
            with _readonly_connection(self.path) as connection:
                rows = connection.execute("SELECT * FROM graph_events ORDER BY sequence").fetchall()
                events = tuple(_event_from_row(row, campaign_id=self._campaign_id) for row in rows)
                _require_event_chain(events, campaign_id=self._campaign_id)
                return events
        except sqlite3.Error as exc:
            raise GraphEventLogError("Graph Event Log read failed") from exc

    def _require_next_event(
        self,
        connection: sqlite3.Connection,
        event: GraphAdmissionEvent,
    ) -> None:
        row = connection.execute(
            """
            SELECT sequence, event_digest FROM graph_events
            ORDER BY sequence DESC
            LIMIT 1
            """
        ).fetchone()
        expected_sequence = cast(int, row["sequence"]) + 1 if row else 1
        expected_previous = cast(str, row["event_digest"]) if row else None
        if event.sequence != expected_sequence or event.previous_event_digest != expected_previous:
            raise GraphEventLogError("Graph event sequence or predecessor is stale")
        duplicate = connection.execute(
            """
            SELECT 1 FROM graph_events
            WHERE event_id = ? OR (proposal_id = ? AND proposal_digest = ?)
            LIMIT 1
            """,
            (event.event_id, event.proposal_id, event.proposal_digest),
        ).fetchone()
        if duplicate is not None:
            raise GraphEventLogError("Graph semantic attempt is already recorded")

        proposed = {
            node.node_id: (node.campaign_id, GraphNodeKind(node.kind))
            for node in event.admitted_nodes
        }
        for edge in event.admitted_edges:
            for reference in (edge.source, edge.target):
                identity = proposed.get(reference.node_id)
                if identity is None:
                    row = connection.execute(
                        "SELECT * FROM graph_nodes WHERE node_id = ?",
                        (reference.node_id,),
                    ).fetchone()
                    if row is None:
                        raise GraphEventLogError("Graph event contains a dangling edge")
                    existing = _node_from_row(row, campaign_id=self._campaign_id)
                    identity = (existing.campaign_id, GraphNodeKind(existing.kind))
                if identity != (reference.campaign_id, reference.kind):
                    raise GraphEventLogError("Graph event edge identity is inconsistent")

    def _record_nodes(
        self,
        connection: sqlite3.Connection,
        event: GraphAdmissionEvent,
    ) -> None:
        for node in event.admitted_nodes:
            existing_row = connection.execute(
                "SELECT * FROM graph_nodes WHERE node_id = ?",
                (node.node_id,),
            ).fetchone()
            if existing_row is not None:
                if _node_from_row(existing_row, campaign_id=self._campaign_id) != node:
                    raise GraphEventLogError("canonical Graph node identity has equivocated")
                continue
            connection.execute(
                """
                INSERT INTO graph_nodes (
                    node_id, node_kind, admitted_sequence, node_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    node.node_id,
                    GraphNodeKind(node.kind).value,
                    event.sequence,
                    sqlite3.Binary(_node_bytes(node)),
                ),
            )


class SQLiteGraphProjectionStore:
    """Append-only projection history with cross-process revision/head CAS."""

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        self.path = _absolute_path(path)
        self._campaign_id = campaign_id

    def current(self) -> GraphProjection:
        try:
            with _readonly_connection(self.path) as connection:
                return _current_projection(connection, campaign_id=self._campaign_id)
        except sqlite3.Error as exc:
            raise GraphProjectionError("Graph projection read failed") from exc

    def compare_and_advance(
        self,
        events: Iterable[GraphAdmissionEvent],
        *,
        expected_revision: int,
        expected_head_digest: str | None,
    ) -> GraphProjectionAdvanceResult:
        canonical_events = tuple(_canonical_event(event) for event in events)
        candidate = GraphProjector.project(
            campaign_id=self._campaign_id,
            events=canonical_events,
        )
        try:
            with _write_transaction(self.path) as connection:
                authoritative_events = _events_from_connection(
                    connection,
                    campaign_id=self._campaign_id,
                )
                if (
                    len(canonical_events) > len(authoritative_events)
                    or canonical_events != authoritative_events[: len(canonical_events)]
                ):
                    raise GraphProjectionConflict(
                        "Graph projection input differs from the durable Event Log prefix"
                    )
                current = _current_projection(
                    connection,
                    campaign_id=self._campaign_id,
                )
                if (
                    expected_revision != current.revision
                    or expected_head_digest != current.event_log_head_digest
                ):
                    raise GraphProjectionConflict(
                        "Graph projection revision compare-and-set failed"
                    )
                if candidate.revision < current.revision:
                    raise GraphProjectionConflict("Graph projection rollback was rejected")
                prefix = GraphProjector.project(
                    campaign_id=self._campaign_id,
                    events=canonical_events[: current.revision],
                )
                if prefix.projection_digest != current.projection_digest:
                    raise GraphProjectionConflict(
                        "Graph Event Log prefix differs from current projection"
                    )
                applied = candidate.revision - current.revision
                if applied:
                    connection.execute(
                        """
                        INSERT INTO graph_projections (
                            revision, event_log_head_digest, projection_id,
                            projection_digest, projection_json
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            candidate.revision,
                            candidate.event_log_head_digest,
                            candidate.projection_id,
                            candidate.projection_digest,
                            sqlite3.Binary(_projection_bytes(candidate)),
                        ),
                    )
                observed = (
                    _current_projection(connection, campaign_id=self._campaign_id)
                    if applied
                    else current
                )
                return GraphProjectionAdvanceResult(
                    projection=observed,
                    previousRevision=current.revision,
                    appliedEventCount=applied,
                    idempotent=not applied,
                )
        except sqlite3.IntegrityError as exc:
            raise GraphProjectionConflict("Graph projection publication conflicted") from exc
        except sqlite3.Error as exc:
            raise GraphProjectionError("Graph projection publication failed") from exc


class SQLiteGraphSnapshotStore:
    """SQLite-backed immutable Snapshot chain with exact-reference resolution."""

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        self.path = _absolute_path(path)
        self._campaign_id = campaign_id
        self._writer: object | None = None
        self._writer_identity: tuple[str, str] | None = None
        self._lock = threading.RLock()

    def claim_writer(self, creator_id: str, creator_digest: str) -> object:
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", creator_id) is None
            or fullmatch(r"^[a-f0-9]{64}$", creator_digest) is None
        ):
            raise GraphSnapshotError("Graph Snapshot writer identity is invalid")
        with self._lock:
            if self._writer is not None:
                raise GraphSnapshotError("Graph Snapshot writer is already claimed")
            try:
                with _write_transaction(self.path) as connection:
                    _pin_writer(
                        connection,
                        writer_kind="snapshot",
                        writer_id=creator_id,
                        writer_digest=creator_digest,
                    )
            except sqlite3.Error as exc:
                raise GraphSnapshotError("Graph Snapshot writer claim failed") from exc
            writer = object()
            self._writer = writer
            self._writer_identity = (creator_id, creator_digest)
            return writer

    def head_digest(self) -> str | None:
        try:
            with _readonly_connection(self.path) as connection:
                return _snapshot_head_digest(connection)
        except sqlite3.Error as exc:
            raise GraphSnapshotError("Graph Snapshot head lookup failed") from exc

    def append(self, snapshot: GraphSnapshot, *, writer: object) -> GraphSnapshot:
        with self._lock:
            if writer is not self._writer or self._writer_identity is None:
                raise GraphSnapshotError("Graph Snapshot write authority is invalid")
            stored = _canonical_snapshot(snapshot)
            if stored.campaign_id != self._campaign_id:
                raise GraphSnapshotError("Graph Snapshot belongs to another Campaign")
            if self._writer_identity != (stored.creator_id, stored.creator_digest):
                raise GraphSnapshotError("Graph Snapshot creator differs from claimed writer")
            try:
                with _write_transaction(self.path) as connection:
                    if _writer_identity(connection, "snapshot") != self._writer_identity:
                        raise GraphSnapshotError(
                            "Graph Snapshot creator differs from durable writer identity"
                        )
                    existing = connection.execute(
                        "SELECT * FROM graph_snapshots WHERE snapshot_id = ?",
                        (stored.snapshot_id,),
                    ).fetchone()
                    if existing is not None:
                        resolved = _snapshot_from_row(
                            existing,
                            campaign_id=self._campaign_id,
                        )
                        if resolved != stored:
                            raise GraphSnapshotError("Graph Snapshot identity has equivocated")
                        return resolved
                    if stored.previous_snapshot_digest != _snapshot_head_digest(connection):
                        raise GraphSnapshotError("Graph Snapshot predecessor is stale")
                    projection = connection.execute(
                        """
                        SELECT * FROM graph_projections
                        WHERE revision = ? AND projection_digest = ?
                        """,
                        (stored.revision, stored.projection_digest),
                    ).fetchone()
                    if (
                        projection is None
                        or _projection_from_row(
                            projection,
                            campaign_id=self._campaign_id,
                        )
                        != stored.projection
                    ):
                        raise GraphSnapshotError(
                            "Graph Snapshot projection is not durably published"
                        )
                    ordinal_row = connection.execute(
                        "SELECT COALESCE(MAX(ordinal), 0) + 1 AS next_ordinal FROM graph_snapshots"
                    ).fetchone()
                    assert ordinal_row is not None
                    connection.execute(
                        """
                        INSERT INTO graph_snapshots (
                            ordinal, snapshot_id, snapshot_digest,
                            previous_snapshot_digest, revision,
                            projection_digest, snapshot_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            cast(int, ordinal_row["next_ordinal"]),
                            stored.snapshot_id,
                            stored.snapshot_digest,
                            stored.previous_snapshot_digest,
                            stored.revision,
                            stored.projection_digest,
                            sqlite3.Binary(_snapshot_bytes(stored)),
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                raise GraphSnapshotError("Graph Snapshot append conflicted") from exc
            except sqlite3.Error as exc:
                raise GraphSnapshotError("Graph Snapshot append failed") from exc
            return _canonical_snapshot(stored)

    def resolve(self, reference: GraphSnapshotRef) -> GraphSnapshot:
        try:
            reference = GraphSnapshotRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except ValidationError as exc:
            raise GraphSnapshotError("Graph Snapshot reference is invalid") from exc
        if reference.campaign_id != self._campaign_id:
            raise GraphSnapshotError("Graph Snapshot reference belongs to another Campaign")
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    "SELECT * FROM graph_snapshots WHERE snapshot_id = ?",
                    (reference.snapshot_id,),
                ).fetchone()
                if row is None:
                    raise GraphSnapshotError("Graph Snapshot was not found")
                resolved = _snapshot_from_row(row, campaign_id=self._campaign_id)
        except sqlite3.Error as exc:
            raise GraphSnapshotError("Graph Snapshot resolution failed") from exc
        if (
            resolved.snapshot_digest,
            resolved.campaign_id,
            resolved.graph_schema_version,
            resolved.revision,
            resolved.event_log_head_digest,
            resolved.projection_digest,
        ) != (
            reference.snapshot_digest,
            reference.campaign_id,
            reference.graph_schema_version,
            reference.revision,
            reference.event_log_head_digest,
            reference.projection_digest,
        ):
            raise GraphSnapshotError("Graph Snapshot reference differs from stored authority")
        return resolved

    def snapshots(self) -> tuple[GraphSnapshot, ...]:
        try:
            with _readonly_connection(self.path) as connection:
                rows = connection.execute(
                    "SELECT * FROM graph_snapshots ORDER BY ordinal"
                ).fetchall()
                snapshots = tuple(
                    _snapshot_from_row(row, campaign_id=self._campaign_id) for row in rows
                )
        except sqlite3.Error as exc:
            raise GraphSnapshotError("Graph Snapshot chain read failed") from exc
        previous: str | None = None
        for snapshot in snapshots:
            if snapshot.previous_snapshot_digest != previous:
                raise GraphSnapshotError("Graph Snapshot chain is not contiguous")
            previous = snapshot.snapshot_digest
        return snapshots


class SQLiteGraphActionPermitStore:
    """Final revision check plus consumed-on-issuance Permit transaction."""

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        self.path = _absolute_path(path)
        self._campaign_id = campaign_id
        self._writer: object | None = None
        self._writer_identity: tuple[str, str, str] | None = None
        self._plain_writer: object | None = None
        self._plain_policies: ActionApprovalCapabilityPolicyRegistry | None = None
        self._plain_policy_digest: str | None = None
        self._approved_writer: object | None = None
        self._approved_policies: ActionApprovalCapabilityPolicyRegistry | None = None
        self._approved_policy_digest: str | None = None
        self._approved_input_authority: ActionApprovalInputAuthority | None = None
        self._approved_reversible_policies: ActionApprovalCapabilityPolicyRegistry | None = None
        self._approved_reversible_policy_digest: str | None = None
        self._approved_reversible_approval_claim_authority: object | None = None
        self._approved_reversible_cleanup_claim_authority: object | None = None
        self._approved_reversible_writers: dict[
            object,
            tuple[ActionApprovalInputAuthority, ReversibleActionPermitInputAuthority],
        ] = {}
        self._reversible_policies: ActionApprovalCapabilityPolicyRegistry | None = None
        self._reversible_policy_digest: str | None = None
        self._reversible_claim_authority: object | None = None
        self._reversible_writers: dict[object, ReversibleActionPermitInputAuthority] = {}
        self._cleanup_claim_authority: object | None = None
        self._cleanup_writers: dict[object, CleanupPermitInputAuthority] = {}
        self._lock = threading.RLock()

    def claim_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
    ) -> object:
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", compiler_id) is None
            or fullmatch(
                r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
                compiler_version,
            )
            is None
            or fullmatch(r"^[a-f0-9]{64}$", compiler_digest) is None
        ):
            raise ActionPermitError("ActionPermit compiler identity is invalid")
        with self._lock:
            if self._writer is not None:
                if self._writer_identity == (
                    compiler_id,
                    compiler_version,
                    compiler_digest,
                ):
                    return self._writer
                raise ActionPermitError("ActionPermit compiler writer is already claimed")
            identity = (compiler_id, compiler_version, compiler_digest)
            try:
                with _write_transaction(self.path) as connection:
                    _pin_action_permit_writer(connection, identity)
            except sqlite3.Error as exc:
                raise ActionPermitError("ActionPermit compiler claim failed") from exc
            writer = object()
            self._writer = writer
            self._writer_identity = identity
            return writer

    def claim_plain_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        policies: ActionCapabilityExecutionPolicyRegistry,
    ) -> object:
        """Pin the no-write policy registry to a non-transferable writer token."""

        canonical_policies = _canonical_action_policy_registry(
            policies,
            label="plain Action writer",
        )
        self.claim_writer(compiler_id, compiler_version, compiler_digest)
        with self._lock:
            if self._plain_writer is not None:
                if self._plain_policy_digest == canonical_policies.registry_digest:
                    return self._plain_writer
                raise ActionPermitError("plain Action writer is already claimed")
            writer = object()
            self._plain_writer = writer
            self._plain_policies = canonical_policies
            self._plain_policy_digest = canonical_policies.registry_digest
            return writer

    def claim_approved_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        policies: ActionApprovalCapabilityPolicyRegistry,
        input_authority: ActionApprovalInputAuthority,
    ) -> object:
        """Pin the approval policy and issuer verifier to one in-process writer."""

        if not isinstance(policies, ActionApprovalCapabilityPolicyRegistry):
            raise TypeError("approved Action writer requires a Capability policy registry")
        if not callable(getattr(input_authority, "verify_action_approval", None)):
            raise TypeError("approved Action writer requires an approval input authority")
        canonical_policies = _canonical_action_policy_registry(
            policies,
            label="approved Action writer",
        )
        self.claim_writer(compiler_id, compiler_version, compiler_digest)
        with self._lock:
            if self._approved_writer is not None:
                if (
                    self._approved_policy_digest == canonical_policies.registry_digest
                    and self._approved_input_authority is input_authority
                ):
                    return self._approved_writer
                raise ActionApprovalError("approved Action writer is already claimed")
            writer = object()
            self._approved_writer = writer
            self._approved_policies = canonical_policies
            self._approved_policy_digest = canonical_policies.registry_digest
            self._approved_input_authority = input_authority
            return writer

    def claim_reversible_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        policies: ActionCapabilityExecutionPolicyRegistry,
        input_authority: ReversibleActionPermitInputAuthority,
        claim_authority: object,
    ) -> object:
        """Pin reversible-write policy and authentication to a distinct writer."""

        canonical_policies = _canonical_action_policy_registry(
            policies,
            label="reversible Action writer",
        )
        if not callable(getattr(input_authority, "verify_reversible_action", None)):
            raise TypeError("reversible Action writer requires an input authority")
        self.claim_writer(compiler_id, compiler_version, compiler_digest)
        with self._lock:
            if self._reversible_claim_authority is not None and (
                self._reversible_policy_digest != canonical_policies.registry_digest
                or self._reversible_claim_authority is not claim_authority
            ):
                raise CleanupPermitError("reversible Action writer is already claimed")
            writer = object()
            if self._reversible_claim_authority is None:
                self._reversible_policies = canonical_policies
                self._reversible_policy_digest = canonical_policies.registry_digest
                self._reversible_claim_authority = claim_authority
            self._reversible_writers[writer] = input_authority
            return writer

    def claim_approved_reversible_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        policies: ActionApprovalCapabilityPolicyRegistry,
        approval_input_authority: ActionApprovalInputAuthority,
        reversible_input_authority: ReversibleActionPermitInputAuthority,
        approval_claim_authority: object,
        cleanup_claim_authority: object,
    ) -> object:
        """Pin both approval and cleanup-hold verifiers to a distinct writer."""

        if not callable(
            getattr(approval_input_authority, "verify_action_approval", None)
        ):
            raise TypeError("approved reversible writer requires an approval verifier")
        if not callable(
            getattr(reversible_input_authority, "verify_reversible_action", None)
        ):
            raise TypeError("approved reversible writer requires a cleanup-hold verifier")
        canonical_policies = _canonical_action_policy_registry(
            policies,
            label="approved reversible Action writer",
        )
        self.claim_writer(compiler_id, compiler_version, compiler_digest)
        with self._lock:
            if self._approved_reversible_policy_digest is not None and (
                self._approved_reversible_policy_digest
                != canonical_policies.registry_digest
                or self._approved_reversible_approval_claim_authority
                is not approval_claim_authority
                or self._approved_reversible_cleanup_claim_authority
                is not cleanup_claim_authority
            ):
                raise ApprovedReversibleActionError(
                    "approved reversible Action writer is already claimed"
                )
            writer = object()
            if self._approved_reversible_policy_digest is None:
                self._approved_reversible_policies = canonical_policies
                self._approved_reversible_policy_digest = (
                    canonical_policies.registry_digest
                )
                self._approved_reversible_approval_claim_authority = (
                    approval_claim_authority
                )
                self._approved_reversible_cleanup_claim_authority = (
                    cleanup_claim_authority
                )
            self._approved_reversible_writers[writer] = (
                approval_input_authority,
                reversible_input_authority,
            )
            return writer

    def claim_cleanup_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        input_authority: CleanupPermitInputAuthority,
        claim_authority: object,
    ) -> object:
        """Pin cleanup authentication to a distinct non-transferable writer."""

        if not callable(getattr(input_authority, "verify_cleanup_request", None)):
            raise TypeError("CleanupPermit writer requires an input authority")
        self.claim_writer(compiler_id, compiler_version, compiler_digest)
        with self._lock:
            if (
                self._cleanup_claim_authority is not None
                and self._cleanup_claim_authority is not claim_authority
            ):
                raise CleanupPermitError("CleanupPermit writer is already claimed")
            writer = object()
            if self._cleanup_claim_authority is None:
                self._cleanup_claim_authority = claim_authority
            self._cleanup_writers[writer] = input_authority
            return writer

    def authorize_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        capability: RegisteredActionCapability,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> ActionPermitAuthorization:
        with self._lock:
            if (
                writer is not self._plain_writer
                or self._writer_identity is None
                or self._plain_policies is None
            ):
                raise ActionPermitError("ActionPermit compiler write authority is invalid")
            envelope = _canonical_mission_envelope(envelope)
            proposal = _canonical_action_proposal(proposal)
            decision = _canonical_graph_decision(decision)
            capability = _canonical_registered_capability(capability)
            policy = self._plain_policies.resolve(capability.reference())
            validate_plain_action_policy(capability, policy)
            if capability.risk_tier >= ToolRiskTier.T2:
                raise ActionPermitError(
                    "T2 or higher Action requires an approved or reversible Permit authority"
                )
            if (
                envelope.campaign_id != self._campaign_id
                or proposal.campaign_id != self._campaign_id
                or decision.campaign_id != self._campaign_id
            ):
                raise ActionPermitError("ActionPermit input belongs to another Campaign")
            if self._writer_identity != (
                envelope.compiler_id,
                envelope.compiler_version,
                envelope.compiler_digest,
            ):
                raise ActionPermitError("ActionPermit compiler differs from durable writer")
            attempt_id = action_permit_attempt_id(envelope, proposal, decision)
            try:
                with _write_transaction(self.path) as connection:
                    if _action_permit_writer_identity(connection) != self._writer_identity:
                        raise ActionPermitError("ActionPermit compiler differs from durable writer")
                    existing_row = connection.execute(
                        "SELECT * FROM graph_action_permits WHERE permit_id = ?",
                        (attempt_id,),
                    ).fetchone()
                    if existing_row is not None:
                        existing = _action_permit_from_row(
                            existing_row,
                            campaign_id=self._campaign_id,
                        )
                        _require_exact_action_permit_retry(
                            existing,
                            envelope=envelope,
                            proposal=proposal,
                            decision=decision,
                            capability=capability,
                        )
                        return ActionPermitAuthorization(
                            permit=existing,
                            newlyConsumed=False,
                        )
                    collision = connection.execute(
                        """
                        SELECT 1 FROM graph_action_permits
                        WHERE proposal_id = ? OR request_id = ?
                        UNION ALL
                        SELECT 1 FROM graph_cleanup_permits WHERE request_id = ?
                        LIMIT 1
                        """,
                        (
                            proposal.proposal_id,
                            proposal.request_id,
                            proposal.request_id,
                        ),
                    ).fetchone()
                    if collision is not None:
                        raise ActionPermitConflict(
                            "ActionProposal or request identity is already consumed"
                        )
                    validate_action_authority(
                        envelope,
                        proposal,
                        decision,
                        capability,
                        evaluated_at=evaluated_at,
                    )
                    _require_latest_action_snapshot(
                        connection,
                        campaign_id=self._campaign_id,
                        proposal=proposal,
                        decision=decision,
                    )
                    _require_aggregate_action_budget(
                        connection,
                        envelope=envelope,
                        new_reservations=(proposal.reservation,),
                        evaluated_at=evaluated_at,
                        error_type=ActionPermitBudgetExceeded,
                    )
                    permit = build_action_permit(
                        envelope,
                        proposal,
                        decision,
                        evaluated_at=evaluated_at,
                        permit_ttl=permit_ttl,
                    )
                    if permit.permit_id != attempt_id:
                        raise ActionPermitError(
                            "ActionPermit deterministic attempt identity differs"
                        )
                    _insert_action_permit(connection, permit)
                    return ActionPermitAuthorization(
                        permit=permit,
                        newlyConsumed=True,
                    )
            except sqlite3.IntegrityError as exc:
                raise ActionPermitConflict(
                    "ActionPermit durable compare-and-set conflicted"
                ) from exc
            except sqlite3.Error as exc:
                raise ActionPermitError("ActionPermit authority transaction failed") from exc

    def approved_authorization(
        self,
        approval_id: str,
        permit_id: str,
    ) -> ActionApprovalAuthorization | None:
        """Read one exact terminal approval tuple without granting redispatch authority."""

        if fullmatch(r"^action-approval_[a-f0-9]{64}$", approval_id) is None:
            raise ActionApprovalError("Action approval ID is invalid")
        if fullmatch(r"^action-permit_[a-f0-9]{64}$", permit_id) is None:
            raise ActionApprovalError("approved ActionPermit ID is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                approval_row = connection.execute(
                    "SELECT * FROM graph_action_approval_envelopes WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()
                permit_row = connection.execute(
                    "SELECT * FROM graph_action_permits WHERE permit_id = ?",
                    (permit_id,),
                ).fetchone()
                receipt_rows = connection.execute(
                    """
                    SELECT * FROM graph_action_approval_consumptions
                    WHERE approval_id = ? OR permit_id = ?
                    """,
                    (approval_id, permit_id),
                ).fetchall()
                present = (
                    approval_row is not None,
                    permit_row is not None,
                    bool(receipt_rows),
                )
                if not any(present):
                    return None
                if not all(present) or len(receipt_rows) != 1:
                    raise ActionApprovalError(
                        "approved Action authority is partially committed"
                    )
                assert approval_row is not None
                assert permit_row is not None
                approval = _action_approval_from_row(
                    approval_row,
                    campaign_id=self._campaign_id,
                )
                permit = _action_permit_from_row(
                    permit_row,
                    campaign_id=self._campaign_id,
                )
                receipt = _approval_consumption_from_row(
                    receipt_rows[0],
                    campaign_id=self._campaign_id,
                )
                if (
                    approval.approval_id != approval_id
                    or permit.permit_id != permit_id
                    or receipt
                    != build_action_approval_consumption_receipt(approval, permit)
                ):
                    raise ActionApprovalError(
                        "approved Action terminal authority differs"
                    )
                return ActionApprovalAuthorization(
                    approval=approval,
                    action=ActionPermitAuthorization(
                        permit=permit,
                        newlyConsumed=False,
                    ),
                    receipt=receipt,
                )
        except sqlite3.Error as exc:
            raise ActionApprovalError("approved Action terminal lookup failed") from exc

    def authorize_approved_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        capability: RegisteredActionCapability,
        approval: ActionApprovalEnvelope,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> ActionApprovalAuthorization:
        """Atomically consume one approval with its exact ActionPermit and receipt."""

        with self._lock:
            if (
                writer is not self._approved_writer
                or self._writer_identity is None
                or self._approved_policies is None
                or self._approved_input_authority is None
            ):
                raise ActionApprovalError("approved Action compiler write authority is invalid")
            envelope = _canonical_mission_envelope(envelope)
            proposal = _canonical_action_proposal(proposal)
            decision = _canonical_graph_decision(decision)
            capability = _canonical_registered_capability(capability)
            try:
                policy = ActionApprovalCapabilityPolicy.model_validate(
                    self._approved_policies.resolve(capability.reference()).model_dump(
                        mode="json",
                        by_alias=True,
                    )
                )
            except (AttributeError, ValidationError, ValueError) as exc:
                raise ActionApprovalError(
                    "approved Action Capability policy is not canonical"
                ) from exc
            approval = _canonical_action_approval(approval)
            self._verify_pinned_approval_input(envelope, proposal, decision, approval)
            if (
                envelope.campaign_id != self._campaign_id
                or proposal.campaign_id != self._campaign_id
                or decision.campaign_id != self._campaign_id
                or approval.campaign_id != self._campaign_id
            ):
                raise ActionApprovalError("approved Action input belongs to another Campaign")
            if self._writer_identity != (
                envelope.compiler_id,
                envelope.compiler_version,
                envelope.compiler_digest,
            ):
                raise ActionApprovalError("approved Action compiler differs from durable writer")
            attempt_id = action_permit_attempt_id(envelope, proposal, decision)
            try:
                with _write_transaction(self.path) as connection:
                    if _action_permit_writer_identity(connection) != self._writer_identity:
                        raise ActionApprovalError(
                            "approved Action compiler differs from durable writer"
                        )
                    approval_row = connection.execute(
                        """
                        SELECT * FROM graph_action_approval_envelopes
                        WHERE approval_id = ?
                        """,
                        (approval.approval_id,),
                    ).fetchone()
                    permit_row = connection.execute(
                        "SELECT * FROM graph_action_permits WHERE permit_id = ?",
                        (attempt_id,),
                    ).fetchone()
                    receipt_row = connection.execute(
                        """
                        SELECT * FROM graph_action_approval_consumptions
                        WHERE permit_id = ?
                        """,
                        (attempt_id,),
                    ).fetchone()
                    existing = (approval_row, permit_row, receipt_row)
                    if any(row is not None for row in existing):
                        if not all(row is not None for row in existing):
                            raise ActionApprovalError(
                                "approved Action authority is partially committed"
                            )
                        assert approval_row is not None
                        assert permit_row is not None
                        assert receipt_row is not None
                        stored_approval = _action_approval_from_row(
                            approval_row,
                            campaign_id=self._campaign_id,
                        )
                        permit = _action_permit_from_row(
                            permit_row,
                            campaign_id=self._campaign_id,
                        )
                        receipt = _approval_consumption_from_row(
                            receipt_row,
                            campaign_id=self._campaign_id,
                        )
                        if stored_approval != approval:
                            raise ActionApprovalError(
                                "approved Action exact retry names another approval"
                            )
                        _require_exact_action_permit_retry(
                            permit,
                            envelope=envelope,
                            proposal=proposal,
                            decision=decision,
                            capability=capability,
                        )
                        expected_receipt = build_action_approval_consumption_receipt(
                            stored_approval,
                            permit,
                        )
                        if receipt != expected_receipt:
                            raise ActionApprovalError("approved Action exact retry receipt differs")
                        authorization = ActionApprovalAuthorization(
                            approval=stored_approval,
                            action=ActionPermitAuthorization(
                                permit=permit,
                                newlyConsumed=False,
                            ),
                            receipt=receipt,
                        )
                    else:
                        collision = connection.execute(
                            """
                            SELECT 1 FROM graph_action_approval_envelopes
                            WHERE proposal_id = ? OR request_id = ?
                            UNION ALL
                            SELECT 1 FROM graph_action_approval_consumptions
                            WHERE approval_id = ? OR proposal_id = ? OR request_id = ?
                            UNION ALL
                            SELECT 1 FROM graph_action_permits
                            WHERE proposal_id = ? OR request_id = ?
                            UNION ALL
                            SELECT 1 FROM graph_cleanup_permits WHERE request_id = ?
                            LIMIT 1
                            """,
                            (
                                proposal.proposal_id,
                                proposal.request_id,
                                approval.approval_id,
                                proposal.proposal_id,
                                proposal.request_id,
                                proposal.proposal_id,
                                proposal.request_id,
                                proposal.request_id,
                            ),
                        ).fetchone()
                        if collision is not None:
                            raise ActionApprovalError(
                                "approved Action identity is already consumed"
                            )
                        validate_action_approval_authority(
                            envelope,
                            proposal,
                            decision,
                            capability,
                            policy,
                            approval,
                            evaluated_at=evaluated_at,
                        )
                        _require_latest_action_snapshot(
                            connection,
                            campaign_id=self._campaign_id,
                            proposal=proposal,
                            decision=decision,
                        )
                        _require_aggregate_action_budget(
                            connection,
                            envelope=envelope,
                            new_reservations=(proposal.reservation,),
                            evaluated_at=evaluated_at,
                            error_type=ActionPermitBudgetExceeded,
                        )
                        permit = build_action_permit(
                            envelope,
                            proposal,
                            decision,
                            evaluated_at=evaluated_at,
                            permit_ttl=permit_ttl,
                        )
                        if permit.permit_id != attempt_id:
                            raise ActionApprovalError(
                                "approved ActionPermit deterministic identity differs"
                            )
                        receipt = build_action_approval_consumption_receipt(
                            approval,
                            permit,
                        )
                        _insert_action_approval(connection, approval)
                        _insert_action_permit(connection, permit)
                        _insert_approval_consumption(connection, receipt)
                        authorization = ActionApprovalAuthorization(
                            approval=approval,
                            action=ActionPermitAuthorization(
                                permit=permit,
                                newlyConsumed=True,
                            ),
                            receipt=receipt,
                        )
                    self._verify_pinned_approval_input(
                        envelope,
                        proposal,
                        decision,
                        approval,
                    )
            except sqlite3.IntegrityError as exc:
                raise ActionApprovalError(
                    "approved Action durable compare-and-set conflicted"
                ) from exc
            except sqlite3.Error as exc:
                raise ActionApprovalError("approved Action authority transaction failed") from exc
            return authorization

    def approved_reversible_authorization(
        self,
        approval_id: str,
        permit_id: str,
    ) -> ApprovedReversibleActionPermitAuthorization | None:
        """Read one terminal approval, Permit, receipt, and cleanup-hold tuple."""

        if fullmatch(r"^action-approval_[a-f0-9]{64}$", approval_id) is None:
            raise ApprovedReversibleActionError("approved reversible approval ID is invalid")
        if fullmatch(r"^action-permit_[a-f0-9]{64}$", permit_id) is None:
            raise ApprovedReversibleActionError("approved reversible Permit ID is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                approval_row = connection.execute(
                    "SELECT * FROM graph_action_approval_envelopes WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()
                permit_row = connection.execute(
                    "SELECT * FROM graph_action_permits WHERE permit_id = ?",
                    (permit_id,),
                ).fetchone()
                receipt_rows = connection.execute(
                    """
                    SELECT * FROM graph_action_approval_consumptions
                    WHERE approval_id = ? OR permit_id = ?
                    """,
                    (approval_id, permit_id),
                ).fetchall()
                reservation_row = connection.execute(
                    """
                    SELECT * FROM graph_action_cleanup_reservations
                    WHERE source_action_permit_id = ?
                    """,
                    (permit_id,),
                ).fetchone()
                present = (
                    approval_row is not None,
                    permit_row is not None,
                    bool(receipt_rows),
                    reservation_row is not None,
                )
                if not any(present):
                    return None
                if not all(present) or len(receipt_rows) != 1:
                    raise ApprovedReversibleActionError(
                        "approved reversible authority is partially committed"
                    )
                assert approval_row is not None
                assert permit_row is not None
                assert reservation_row is not None
                approval, permit, receipt, reservation = (
                    _approved_reversible_records_from_rows(
                        approval_row,
                        permit_row,
                        receipt_rows[0],
                        reservation_row,
                        campaign_id=self._campaign_id,
                    )
                )
                if (
                    approval.approval_id != approval_id
                    or permit.permit_id != permit_id
                    or receipt
                    != build_action_approval_consumption_receipt(approval, permit)
                    or reservation.source_action_permit_id != permit.permit_id
                    or reservation.source_action_permit_digest != permit.permit_digest
                    or reservation.source_action_dispatch_id != permit.dispatch_id
                ):
                    raise ApprovedReversibleActionError(
                        "approved reversible terminal authority differs"
                    )
                return _approved_reversible_authorization(
                    approval,
                    permit,
                    receipt,
                    reservation,
                    newly_consumed=False,
                )
        except sqlite3.Error as exc:
            raise ApprovedReversibleActionError(
                "approved reversible terminal lookup failed"
            ) from exc

    def authorize_approved_reversible_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        action_capability: RegisteredActionCapability,
        approval: ActionApprovalEnvelope,
        cleanup_request: ActionCleanupReservationRequest,
        cleanup_capability: RegisteredActionCapability,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> ApprovedReversibleActionPermitAuthorization:
        """Atomically consume approval, Permit, receipt, and cleanup capacity."""

        with self._lock:
            verifier_pair = self._approved_reversible_writers.get(writer)
            if (
                verifier_pair is None
                or self._writer_identity is None
                or self._approved_reversible_policies is None
            ):
                raise ApprovedReversibleActionError(
                    "approved reversible compiler write authority is invalid"
                )
            envelope = _canonical_mission_envelope(envelope)
            proposal = _canonical_action_proposal(proposal)
            decision = _canonical_graph_decision(decision)
            action_capability = _canonical_registered_capability(action_capability)
            policy = self._approved_reversible_policies.resolve(
                action_capability.reference()
            )
            approval = _canonical_action_approval(approval)
            cleanup_request = _canonical_cleanup_reservation_request(cleanup_request)
            cleanup_capability = _canonical_registered_capability(cleanup_capability)
            self._verify_pinned_approved_reversible_inputs(
                envelope,
                proposal,
                decision,
                approval,
                cleanup_request,
                writer=writer,
            )
            if (
                envelope.campaign_id != self._campaign_id
                or proposal.campaign_id != self._campaign_id
                or decision.campaign_id != self._campaign_id
                or approval.campaign_id != self._campaign_id
                or cleanup_request.campaign_id != self._campaign_id
            ):
                raise ApprovedReversibleActionError(
                    "approved reversible input belongs to another Campaign"
                )
            if self._writer_identity != (
                envelope.compiler_id,
                envelope.compiler_version,
                envelope.compiler_digest,
            ):
                raise ApprovedReversibleActionError(
                    "approved reversible compiler differs from durable writer"
                )
            attempt_id = action_permit_attempt_id(envelope, proposal, decision)
            try:
                with _write_transaction(self.path) as connection:
                    if _action_permit_writer_identity(connection) != self._writer_identity:
                        raise ApprovedReversibleActionError(
                            "approved reversible compiler differs from durable writer"
                        )
                    existing = _approved_reversible_transaction_rows(
                        connection,
                        approval_id=approval.approval_id,
                        permit_id=attempt_id,
                    )
                    approval_row, permit_row, receipt_row, reservation_row = existing
                    if any(row is not None for row in existing):
                        if not all(row is not None for row in existing):
                            raise ApprovedReversibleActionError(
                                "approved reversible authority is partially committed"
                            )
                        assert approval_row is not None
                        assert permit_row is not None
                        assert receipt_row is not None
                        assert reservation_row is not None
                        stored_approval, permit, receipt, reservation = (
                            _approved_reversible_records_from_rows(
                                approval_row,
                                permit_row,
                                receipt_row,
                                reservation_row,
                                campaign_id=self._campaign_id,
                            )
                        )
                        if stored_approval != approval:
                            raise ApprovedReversibleActionError(
                                "approved reversible retry names another approval"
                            )
                        _require_exact_action_permit_retry(
                            permit,
                            envelope=envelope,
                            proposal=proposal,
                            decision=decision,
                            capability=action_capability,
                        )
                        _require_exact_cleanup_reservation_retry(
                            reservation,
                            envelope=envelope,
                            action_permit=permit,
                            request=cleanup_request,
                            cleanup_capability=cleanup_capability,
                        )
                        if receipt != build_action_approval_consumption_receipt(
                            stored_approval,
                            permit,
                        ):
                            raise ApprovedReversibleActionError(
                                "approved reversible retry receipt differs"
                            )
                        authorization = _approved_reversible_authorization(
                            stored_approval,
                            permit,
                            receipt,
                            reservation,
                            newly_consumed=False,
                        )
                    else:
                        if _approved_reversible_identity_is_consumed(
                            connection,
                            approval=approval,
                            proposal=proposal,
                            cleanup_request=cleanup_request,
                        ):
                            raise ApprovedReversibleActionError(
                                "approved reversible identity is already consumed"
                            )
                        validate_approved_reversible_action_authority(
                            envelope,
                            proposal,
                            decision,
                            action_capability,
                            policy,
                            approval,
                            cleanup_request,
                            cleanup_capability,
                            evaluated_at=evaluated_at,
                        )
                        _require_latest_action_snapshot(
                            connection,
                            campaign_id=self._campaign_id,
                            proposal=proposal,
                            decision=decision,
                        )
                        _require_aggregate_action_budget(
                            connection,
                            envelope=envelope,
                            new_reservations=(
                                proposal.reservation,
                                cleanup_request.reservation,
                            ),
                            evaluated_at=evaluated_at,
                            error_type=CleanupPermitBudgetExceeded,
                        )
                        permit = build_action_permit(
                            envelope,
                            proposal,
                            decision,
                            evaluated_at=evaluated_at,
                            permit_ttl=permit_ttl,
                        )
                        if permit.permit_id != attempt_id:
                            raise ApprovedReversibleActionError(
                                "approved reversible Permit identity differs"
                            )
                        receipt = build_action_approval_consumption_receipt(
                            approval,
                            permit,
                        )
                        reservation = build_action_cleanup_reservation(
                            envelope,
                            permit,
                            cleanup_request,
                            evaluated_at=evaluated_at,
                        )
                        _insert_action_approval(connection, approval)
                        _insert_action_permit(connection, permit)
                        _insert_approval_consumption(connection, receipt)
                        _insert_cleanup_reservation(connection, reservation)
                        authorization = _approved_reversible_authorization(
                            approval,
                            permit,
                            receipt,
                            reservation,
                            newly_consumed=True,
                        )
                    self._verify_pinned_approved_reversible_inputs(
                        envelope,
                        proposal,
                        decision,
                        approval,
                        cleanup_request,
                        writer=writer,
                    )
            except sqlite3.IntegrityError as exc:
                raise ApprovedReversibleActionError(
                    "approved reversible durable compare-and-set conflicted"
                ) from exc
            except sqlite3.Error as exc:
                raise ApprovedReversibleActionError(
                    "approved reversible authority transaction failed"
                ) from exc
            return authorization

    def _verify_pinned_approved_reversible_inputs(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
        cleanup_request: ActionCleanupReservationRequest,
        *,
        writer: object,
    ) -> None:
        authorities = self._approved_reversible_writers.get(writer)
        if authorities is None:
            raise ApprovedReversibleActionError(
                "approved reversible input authorities are not pinned"
            )
        approval_authority, reversible_authority = authorities
        try:
            approval_authority.verify_action_approval(
                envelope.model_copy(deep=True),
                proposal.model_copy(deep=True),
                decision.model_copy(deep=True),
                approval.model_copy(deep=True),
            )
            reversible_authority.verify_reversible_action(
                envelope.model_copy(deep=True),
                proposal.model_copy(deep=True),
                decision.model_copy(deep=True),
                cleanup_request.model_copy(deep=True),
            )
        except ApprovedReversibleActionError:
            raise
        except Exception as exc:
            raise ApprovedReversibleActionError(
                "approved reversible input authority rejected the durable claim"
            ) from exc

    def _verify_pinned_approval_input(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> None:
        authority = self._approved_input_authority
        if authority is None:
            raise ActionApprovalError("approved Action input authority is not pinned")
        try:
            authority.verify_action_approval(
                envelope.model_copy(deep=True),
                proposal.model_copy(deep=True),
                decision.model_copy(deep=True),
                approval.model_copy(deep=True),
            )
        except ActionApprovalError:
            raise
        except Exception as exc:
            raise ActionApprovalError(
                "approved Action input authority rejected the durable claim"
            ) from exc

    def _verify_pinned_reversible_input(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        cleanup_request: ActionCleanupReservationRequest,
        *,
        writer: object,
    ) -> None:
        authority = self._reversible_writers.get(writer)
        if authority is None:
            raise CleanupPermitError("reversible Action input authority is not pinned")
        try:
            authority.verify_reversible_action(
                envelope.model_copy(deep=True),
                proposal.model_copy(deep=True),
                decision.model_copy(deep=True),
                cleanup_request.model_copy(deep=True),
            )
        except CleanupPermitError:
            raise
        except Exception as exc:
            raise CleanupPermitError(
                "reversible Action input authority rejected the durable claim"
            ) from exc

    def _verify_pinned_cleanup_input(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
        *,
        writer: object,
    ) -> None:
        authority = self._cleanup_writers.get(writer)
        if authority is None:
            raise CleanupPermitError("CleanupPermit input authority is not pinned")
        try:
            authority.verify_cleanup_request(
                envelope.model_copy(deep=True),
                request.model_copy(deep=True),
                decision.model_copy(deep=True),
            )
        except CleanupPermitError:
            raise
        except Exception as exc:
            raise CleanupPermitError(
                "CleanupPermit input authority rejected the durable claim"
            ) from exc

    def authorize_reversible_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        action_capability: RegisteredActionCapability,
        cleanup_request: ActionCleanupReservationRequest,
        cleanup_capability: RegisteredActionCapability,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> ReversibleActionPermitAuthorization:
        """Atomically consume one ActionPermit and reserve its cleanup budget."""

        with self._lock:
            if (
                writer not in self._reversible_writers
                or self._writer_identity is None
                or self._reversible_policies is None
            ):
                raise CleanupPermitError("reversible Action compiler write authority is invalid")
            envelope = _canonical_mission_envelope(envelope)
            proposal = _canonical_action_proposal(proposal)
            decision = _canonical_graph_decision(decision)
            action_capability = _canonical_registered_capability(action_capability)
            action_policy = self._reversible_policies.resolve(
                action_capability.reference()
            )
            validate_reversible_action_policy(action_capability, action_policy)
            cleanup_request = _canonical_cleanup_reservation_request(cleanup_request)
            cleanup_capability = _canonical_registered_capability(cleanup_capability)
            self._verify_pinned_reversible_input(
                envelope,
                proposal,
                decision,
                cleanup_request,
                writer=writer,
            )
            if (
                envelope.campaign_id != self._campaign_id
                or proposal.campaign_id != self._campaign_id
                or decision.campaign_id != self._campaign_id
                or cleanup_request.campaign_id != self._campaign_id
            ):
                raise CleanupPermitError(
                    "reversible Action input belongs to another Campaign"
                )
            if self._writer_identity != (
                envelope.compiler_id,
                envelope.compiler_version,
                envelope.compiler_digest,
            ):
                raise CleanupPermitError("reversible Action compiler differs from durable writer")
            attempt_id = action_permit_attempt_id(envelope, proposal, decision)
            try:
                with _write_transaction(self.path) as connection:
                    if _action_permit_writer_identity(connection) != self._writer_identity:
                        raise CleanupPermitError(
                            "reversible Action compiler differs from durable writer"
                        )
                    existing_action_row = connection.execute(
                        "SELECT * FROM graph_action_permits WHERE permit_id = ?",
                        (attempt_id,),
                    ).fetchone()
                    existing_reservation_row = connection.execute(
                        """
                        SELECT * FROM graph_action_cleanup_reservations
                        WHERE source_action_permit_id = ?
                        """,
                        (attempt_id,),
                    ).fetchone()
                    if (existing_action_row is None) is not (
                        existing_reservation_row is None
                    ):
                        raise CleanupPermitError(
                            "reversible Action authority is partially committed"
                        )
                    if existing_action_row is not None:
                        assert existing_reservation_row is not None
                        action = _action_permit_from_row(
                            existing_action_row,
                            campaign_id=self._campaign_id,
                        )
                        reservation = _cleanup_reservation_from_row(
                            existing_reservation_row,
                            campaign_id=self._campaign_id,
                        )
                        _require_exact_action_permit_retry(
                            action,
                            envelope=envelope,
                            proposal=proposal,
                            decision=decision,
                            capability=action_capability,
                        )
                        _require_exact_cleanup_reservation_retry(
                            reservation,
                            envelope=envelope,
                            action_permit=action,
                            request=cleanup_request,
                            cleanup_capability=cleanup_capability,
                        )
                        authorization = ReversibleActionPermitAuthorization(
                            action=ActionPermitAuthorization(
                                permit=action,
                                newlyConsumed=False,
                            ),
                            cleanupReservation=reservation,
                        )
                        self._verify_pinned_reversible_input(
                            envelope,
                            proposal,
                            decision,
                            cleanup_request,
                            writer=writer,
                        )
                        return authorization
                    collision = connection.execute(
                        """
                        SELECT 1
                        FROM graph_action_permits
                        WHERE proposal_id = ? OR request_id = ?
                        UNION ALL
                        SELECT 1
                        FROM graph_cleanup_permits
                        WHERE request_id = ?
                        LIMIT 1
                        """,
                        (
                            proposal.proposal_id,
                            proposal.request_id,
                            proposal.request_id,
                        ),
                    ).fetchone()
                    reservation_collision = connection.execute(
                        """
                        SELECT 1 FROM graph_action_cleanup_reservations
                        WHERE reservation_request_id = ?
                        LIMIT 1
                        """,
                        (cleanup_request.reservation_request_id,),
                    ).fetchone()
                    if collision is not None or reservation_collision is not None:
                        raise CleanupPermitConflict(
                            "reversible Action or cleanup reservation identity is consumed"
                        )
                    validate_action_cleanup_reservation_authority(
                        envelope,
                        proposal,
                        decision,
                        action_capability,
                        action_policy,
                        cleanup_request,
                        cleanup_capability,
                        evaluated_at=evaluated_at,
                    )
                    _require_latest_action_snapshot(
                        connection,
                        campaign_id=self._campaign_id,
                        proposal=proposal,
                        decision=decision,
                    )
                    _require_aggregate_action_budget(
                        connection,
                        envelope=envelope,
                        new_reservations=(
                            proposal.reservation,
                            cleanup_request.reservation,
                        ),
                        evaluated_at=evaluated_at,
                        error_type=CleanupPermitBudgetExceeded,
                    )
                    action = build_action_permit(
                        envelope,
                        proposal,
                        decision,
                        evaluated_at=evaluated_at,
                        permit_ttl=permit_ttl,
                    )
                    if action.permit_id != attempt_id:
                        raise CleanupPermitError(
                            "reversible ActionPermit deterministic identity differs"
                        )
                    reservation = build_action_cleanup_reservation(
                        envelope,
                        action,
                        cleanup_request,
                        evaluated_at=evaluated_at,
                    )
                    _insert_action_permit(connection, action)
                    _insert_cleanup_reservation(connection, reservation)
                    authorization = ReversibleActionPermitAuthorization(
                        action=ActionPermitAuthorization(
                            permit=action,
                            newlyConsumed=True,
                        ),
                        cleanupReservation=reservation,
                    )
                    self._verify_pinned_reversible_input(
                        envelope,
                        proposal,
                        decision,
                        cleanup_request,
                        writer=writer,
                    )
                    return authorization
            except sqlite3.IntegrityError as exc:
                raise CleanupPermitConflict(
                    "reversible Action durable compare-and-set conflicted"
                ) from exc
            except sqlite3.Error as exc:
                raise CleanupPermitError(
                    "reversible Action authority transaction failed"
                ) from exc

    def authorize_cleanup_for_dispatch(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
        capability: RegisteredActionCapability,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> CleanupPermitAuthorization:
        """Consume one pre-reserved CleanupPermit without charging budget twice."""

        with self._lock:
            if (
                writer not in self._cleanup_writers
                or self._writer_identity is None
            ):
                raise CleanupPermitError("CleanupPermit compiler write authority is invalid")
            envelope = _canonical_mission_envelope(envelope)
            request = _canonical_cleanup_request(request)
            decision = _canonical_graph_decision(decision)
            capability = _canonical_registered_capability(capability)
            self._verify_pinned_cleanup_input(
                envelope,
                request,
                decision,
                writer=writer,
            )
            if (
                envelope.campaign_id != self._campaign_id
                or request.campaign_id != self._campaign_id
                or decision.campaign_id != self._campaign_id
            ):
                raise CleanupPermitError("CleanupPermit input belongs to another Campaign")
            if self._writer_identity != (
                envelope.compiler_id,
                envelope.compiler_version,
                envelope.compiler_digest,
            ):
                raise CleanupPermitError("CleanupPermit compiler differs from durable writer")
            attempt_id = cleanup_permit_attempt_id(envelope, request, decision)
            try:
                with _write_transaction(self.path) as connection:
                    if _action_permit_writer_identity(connection) != self._writer_identity:
                        raise CleanupPermitError(
                            "CleanupPermit compiler differs from durable writer"
                        )
                    existing_row = connection.execute(
                        "SELECT * FROM graph_cleanup_permits WHERE cleanup_permit_id = ?",
                        (attempt_id,),
                    ).fetchone()
                    if existing_row is not None:
                        existing = _cleanup_permit_from_row(
                            existing_row,
                            campaign_id=self._campaign_id,
                        )
                        _require_exact_cleanup_permit_retry(
                            existing,
                            envelope=envelope,
                            request=request,
                            decision=decision,
                            capability=capability,
                        )
                        authorization = CleanupPermitAuthorization(
                            permit=existing,
                            newlyConsumed=False,
                        )
                        self._verify_pinned_cleanup_input(
                            envelope,
                            request,
                            decision,
                            writer=writer,
                        )
                        return authorization
                    collision = connection.execute(
                        """
                        SELECT 1 FROM graph_cleanup_permits
                        WHERE cleanup_reservation_id = ?
                           OR source_action_permit_id = ?
                           OR cleanup_request_id = ?
                           OR request_id = ?
                        UNION ALL
                        SELECT 1 FROM graph_action_permits WHERE request_id = ?
                        LIMIT 1
                        """,
                        (
                            request.cleanup_reservation_id,
                            request.source_action_permit_id,
                            request.cleanup_request_id,
                            request.request_id,
                            request.request_id,
                        ),
                    ).fetchone()
                    if collision is not None:
                        raise CleanupPermitConflict(
                            "cleanup reservation, source Action, or request is consumed"
                        )
                    reservation_row = connection.execute(
                        """
                        SELECT * FROM graph_action_cleanup_reservations
                        WHERE cleanup_reservation_id = ?
                        """,
                        (request.cleanup_reservation_id,),
                    ).fetchone()
                    action_row = connection.execute(
                        "SELECT * FROM graph_action_permits WHERE permit_id = ?",
                        (request.source_action_permit_id,),
                    ).fetchone()
                    if reservation_row is None or action_row is None:
                        raise CleanupPermitError(
                            "CleanupRequest has no durable source Action or reservation"
                        )
                    reservation = _cleanup_reservation_from_row(
                        reservation_row,
                        campaign_id=self._campaign_id,
                    )
                    source_action = _action_permit_from_row(
                        action_row,
                        campaign_id=self._campaign_id,
                    )
                    validate_cleanup_authority(
                        envelope,
                        request,
                        decision,
                        capability,
                        source_action,
                        reservation,
                        evaluated_at=evaluated_at,
                    )
                    _require_latest_cleanup_snapshot(
                        connection,
                        campaign_id=self._campaign_id,
                        request=request,
                        decision=decision,
                    )
                    permit = build_cleanup_permit(
                        envelope,
                        request,
                        reservation,
                        evaluated_at=evaluated_at,
                        permit_ttl=permit_ttl,
                    )
                    if permit.cleanup_permit_id != attempt_id:
                        raise CleanupPermitError(
                            "CleanupPermit deterministic attempt identity differs"
                        )
                    _insert_cleanup_permit(connection, permit)
                    authorization = CleanupPermitAuthorization(
                        permit=permit,
                        newlyConsumed=True,
                    )
                    self._verify_pinned_cleanup_input(
                        envelope,
                        request,
                        decision,
                        writer=writer,
                    )
                    return authorization
            except sqlite3.IntegrityError as exc:
                raise CleanupPermitConflict(
                    "CleanupPermit durable compare-and-set conflicted"
                ) from exc
            except sqlite3.Error as exc:
                raise CleanupPermitError("CleanupPermit authority transaction failed") from exc

    def permit(self, permit_id: str) -> ActionPermit | None:
        if fullmatch(r"^action-permit_[a-f0-9]{64}$", permit_id) is None:
            raise ActionPermitError("ActionPermit ID is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    "SELECT * FROM graph_action_permits WHERE permit_id = ?",
                    (permit_id,),
                ).fetchone()
                return (
                    _action_permit_from_row(row, campaign_id=self._campaign_id)
                    if row is not None
                    else None
                )
        except sqlite3.Error as exc:
            raise ActionPermitError("ActionPermit lookup failed") from exc

    def permits(self) -> tuple[ActionPermit, ...]:
        try:
            with _readonly_connection(self.path) as connection:
                rows = connection.execute(
                    "SELECT * FROM graph_action_permits ORDER BY ordinal"
                ).fetchall()
                return tuple(
                    _action_permit_from_row(row, campaign_id=self._campaign_id) for row in rows
                )
        except sqlite3.Error as exc:
            raise ActionPermitError("ActionPermit ledger read failed") from exc

    def action_approval(self, approval_id: str) -> ActionApprovalEnvelope | None:
        if fullmatch(r"^action-approval_[a-f0-9]{64}$", approval_id) is None:
            raise ActionApprovalError("Action approval ID is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    """
                    SELECT * FROM graph_action_approval_envelopes
                    WHERE approval_id = ?
                    """,
                    (approval_id,),
                ).fetchone()
                return (
                    _action_approval_from_row(row, campaign_id=self._campaign_id)
                    if row is not None
                    else None
                )
        except sqlite3.Error as exc:
            raise ActionApprovalError("Action approval lookup failed") from exc

    def action_approvals(self) -> tuple[ActionApprovalEnvelope, ...]:
        try:
            with _readonly_connection(self.path) as connection:
                rows = connection.execute(
                    "SELECT * FROM graph_action_approval_envelopes ORDER BY ordinal"
                ).fetchall()
                return tuple(
                    _action_approval_from_row(row, campaign_id=self._campaign_id) for row in rows
                )
        except sqlite3.Error as exc:
            raise ActionApprovalError("Action approval ledger read failed") from exc

    def approval_consumption(
        self,
        receipt_id: str,
    ) -> ActionApprovalConsumptionReceipt | None:
        if fullmatch(r"^action-approval-receipt_[a-f0-9]{64}$", receipt_id) is None:
            raise ActionApprovalError("Action approval receipt ID is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    """
                    SELECT * FROM graph_action_approval_consumptions
                    WHERE receipt_id = ?
                    """,
                    (receipt_id,),
                ).fetchone()
                return (
                    _approval_consumption_from_row(
                        row,
                        campaign_id=self._campaign_id,
                    )
                    if row is not None
                    else None
                )
        except sqlite3.Error as exc:
            raise ActionApprovalError("Action approval receipt lookup failed") from exc

    def approval_consumptions(self) -> tuple[ActionApprovalConsumptionReceipt, ...]:
        try:
            with _readonly_connection(self.path) as connection:
                rows = connection.execute(
                    "SELECT * FROM graph_action_approval_consumptions ORDER BY ordinal"
                ).fetchall()
                return tuple(
                    _approval_consumption_from_row(
                        row,
                        campaign_id=self._campaign_id,
                    )
                    for row in rows
                )
        except sqlite3.Error as exc:
            raise ActionApprovalError("Action approval receipt ledger read failed") from exc

    def cleanup_reservation(
        self,
        reservation_id: str,
    ) -> ActionCleanupReservation | None:
        if fullmatch(r"^action-cleanup-reservation_[a-f0-9]{64}$", reservation_id) is None:
            raise CleanupPermitError("cleanup reservation ID is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    """
                    SELECT * FROM graph_action_cleanup_reservations
                    WHERE cleanup_reservation_id = ?
                    """,
                    (reservation_id,),
                ).fetchone()
                return (
                    _cleanup_reservation_from_row(row, campaign_id=self._campaign_id)
                    if row is not None
                    else None
                )
        except sqlite3.Error as exc:
            raise CleanupPermitError("cleanup reservation lookup failed") from exc

    def cleanup_reservations(self) -> tuple[ActionCleanupReservation, ...]:
        try:
            with _readonly_connection(self.path) as connection:
                rows = connection.execute(
                    "SELECT * FROM graph_action_cleanup_reservations ORDER BY ordinal"
                ).fetchall()
                return tuple(
                    _cleanup_reservation_from_row(row, campaign_id=self._campaign_id)
                    for row in rows
                )
        except sqlite3.Error as exc:
            raise CleanupPermitError("cleanup reservation ledger read failed") from exc

    def cleanup_permit(self, permit_id: str) -> CleanupPermit | None:
        if fullmatch(r"^cleanup-permit_[a-f0-9]{64}$", permit_id) is None:
            raise CleanupPermitError("CleanupPermit ID is invalid")
        try:
            with _readonly_connection(self.path) as connection:
                row = connection.execute(
                    "SELECT * FROM graph_cleanup_permits WHERE cleanup_permit_id = ?",
                    (permit_id,),
                ).fetchone()
                return (
                    _cleanup_permit_from_row(row, campaign_id=self._campaign_id)
                    if row is not None
                    else None
                )
        except sqlite3.Error as exc:
            raise CleanupPermitError("CleanupPermit lookup failed") from exc

    def cleanup_permits(self) -> tuple[CleanupPermit, ...]:
        try:
            with _readonly_connection(self.path) as connection:
                rows = connection.execute(
                    "SELECT * FROM graph_cleanup_permits ORDER BY ordinal"
                ).fetchall()
                return tuple(
                    _cleanup_permit_from_row(row, campaign_id=self._campaign_id)
                    for row in rows
                )
        except sqlite3.Error as exc:
            raise CleanupPermitError("CleanupPermit ledger read failed") from exc


def sqlite_graph_backup_manifest_path(backup: Path) -> Path:
    """Return the fixed sidecar path for one SQLite Graph backup."""

    normalized = _absolute_path(backup)
    return Path(f"{normalized}.manifest.json")


def _create_backup(
    source: Path,
    destination: Path,
    *,
    campaign_id: str,
    created_at: datetime,
) -> SQLiteGraphBackupManifest:
    backup_path = _absolute_path(destination)
    manifest_path = sqlite_graph_backup_manifest_path(backup_path)
    if backup_path == source or manifest_path == source:
        raise SQLiteGraphStoreError("SQLite Graph backup must not replace the live store")
    _prepare_private_parent(backup_path.parent)
    _require_absent_leaf(backup_path, label="SQLite Graph backup")
    _require_absent_leaf(manifest_path, label="SQLite Graph backup manifest")
    temporary_backup = _private_temporary_path(backup_path)
    temporary_manifest: Path | None = None
    backup_published = False
    try:
        _copy_sqlite_backup(source, temporary_backup, campaign_id=campaign_id)
        state = _verified_graph_store_state(temporary_backup, campaign_id=campaign_id)
        database = read_bounded_regular_bytes(
            temporary_backup,
            max_bytes=_MAX_GRAPH_BACKUP_BYTES,
            label="SQLite Graph backup database",
            require_single_link=True,
        )
        manifest = SQLiteGraphBackupManifest(
            campaignId=campaign_id,
            createdAt=created_at,
            databaseSha256=sha256(database).hexdigest(),
            databaseBytes=len(database),
            eventCount=state.event_count,
            eventLogHeadDigest=state.event_log_head_digest,
            projectionRevision=state.projection_revision,
            projectionDigest=state.projection_digest,
            snapshotCount=state.snapshot_count,
            snapshotHeadDigest=state.snapshot_head_digest,
            actionPermitCount=state.action_permit_count,
            actionPermitHeadDigest=state.action_permit_head_digest,
            cleanupReservationCount=state.cleanup_reservation_count,
            cleanupReservationHeadDigest=state.cleanup_reservation_head_digest,
            cleanupPermitCount=state.cleanup_permit_count,
            cleanupPermitHeadDigest=state.cleanup_permit_head_digest,
            actionApprovalCount=state.action_approval_count,
            actionApprovalHeadDigest=state.action_approval_head_digest,
            approvalConsumptionCount=state.approval_consumption_count,
            approvalConsumptionHeadDigest=state.approval_consumption_head_digest,
        )
        temporary_manifest = _write_private_temporary(
            manifest_path,
            _backup_manifest_bytes(manifest),
        )
        _publish_exclusive(temporary_backup, backup_path, label="SQLite Graph backup")
        backup_published = True
        _publish_exclusive(
            temporary_manifest,
            manifest_path,
            label="SQLite Graph backup manifest",
        )
        temporary_manifest = None
        return manifest
    except (
        ActionApprovalError,
        OSError,
        sqlite3.Error,
        ValidationError,
        ValueError,
        SQLiteGraphStoreError,
    ) as exc:
        if backup_published:
            with suppress(OSError):
                backup_path.unlink()
                _fsync_graph_directory(backup_path.parent)
        if isinstance(exc, SQLiteGraphStoreError):
            raise
        raise SQLiteGraphStoreError("SQLite Graph backup creation failed") from exc
    finally:
        with suppress(FileNotFoundError):
            temporary_backup.unlink()
        if temporary_manifest is not None:
            with suppress(FileNotFoundError):
                temporary_manifest.unlink()


def _parse_backup_manifest(
    raw: bytes,
) -> SQLiteGraphBackupManifest | _SQLiteGraphBackupManifestV2 | _SQLiteGraphBackupManifestV1:
    try:
        material = parse_strict_json_bytes(
            raw,
            label="SQLite Graph backup manifest",
            max_bytes=_MAX_GRAPH_BACKUP_MANIFEST_BYTES,
            max_depth=16,
            max_nodes=96,
        )
        if not isinstance(material, dict):
            raise ValueError("SQLite Graph backup manifest must be an object")
        api_version = material.get("apiVersion")
        if api_version == GRAPH_STORE_BACKUP_MANIFEST_API_VERSION:
            return SQLiteGraphBackupManifest.model_validate(material)
        if api_version == _CLEANUP_GRAPH_STORE_BACKUP_MANIFEST_API_VERSION:
            return _SQLiteGraphBackupManifestV2.model_validate(material)
        if api_version == _LEGACY_GRAPH_STORE_BACKUP_MANIFEST_API_VERSION:
            return _SQLiteGraphBackupManifestV1.model_validate(material)
        raise ValueError("SQLite Graph backup manifest version is unsupported")
    except (ValidationError, ValueError) as exc:
        raise SQLiteGraphStoreError("SQLite Graph backup manifest is invalid") from exc


def _restore_backup(
    backup: Path,
    *,
    destination: Path,
    campaign_id: str,
) -> None:
    backup_path = _absolute_path(backup)
    manifest_path = sqlite_graph_backup_manifest_path(backup_path)
    destination_path = _absolute_path(destination)
    if destination_path in {backup_path, manifest_path}:
        raise SQLiteGraphStoreError("SQLite Graph restore destination overlaps its backup")
    _prepare_private_parent(destination_path.parent)
    _require_absent_leaf(destination_path, label="SQLite Graph restore destination")
    temporary = _private_temporary_path(destination_path)
    try:
        manifest_raw = read_bounded_regular_bytes(
            manifest_path,
            max_bytes=_MAX_GRAPH_BACKUP_MANIFEST_BYTES,
            label="SQLite Graph backup manifest",
            require_single_link=True,
        )
        manifest = _parse_backup_manifest(manifest_raw)
        if manifest_raw != _backup_manifest_bytes(manifest):
            raise SQLiteGraphStoreError("SQLite Graph backup manifest is not canonical bytes")
        if manifest.campaign_id != campaign_id:
            raise SQLiteGraphStoreError("SQLite Graph backup belongs to another Campaign")
        database = read_bounded_regular_bytes(
            backup_path,
            max_bytes=_MAX_GRAPH_BACKUP_BYTES,
            label="SQLite Graph backup database",
            require_single_link=True,
        )
        if (
            len(database) != manifest.database_bytes
            or sha256(database).hexdigest() != manifest.database_sha256
        ):
            raise SQLiteGraphStoreError("SQLite Graph backup database digest differs")
        _write_existing_private_file(temporary, database)
        if isinstance(manifest, _SQLiteGraphBackupManifestV1):
            legacy_state = _verified_v2_graph_store_state(
                temporary,
                campaign_id=campaign_id,
            )
            _require_legacy_manifest_state(manifest, legacy_state)
            _initialize(temporary, campaign_id)
            migrated_state = _verified_graph_store_state(
                temporary,
                campaign_id=campaign_id,
            )
            if (
                migrated_state.cleanup_reservation_count != 0
                or migrated_state.cleanup_permit_count != 0
                or migrated_state.action_approval_count != 0
                or migrated_state.approval_consumption_count != 0
            ):
                raise SQLiteGraphStoreError(
                    "legacy SQLite Graph restore fabricated later authority"
                )
        elif isinstance(manifest, _SQLiteGraphBackupManifestV2):
            cleanup_state = _verified_v3_graph_store_state(
                temporary,
                campaign_id=campaign_id,
            )
            _require_cleanup_manifest_state(manifest, cleanup_state)
            _initialize(temporary, campaign_id)
            migrated_state = _verified_graph_store_state(
                temporary,
                campaign_id=campaign_id,
            )
            if (
                migrated_state.action_approval_count != 0
                or migrated_state.approval_consumption_count != 0
            ):
                raise SQLiteGraphStoreError(
                    "legacy cleanup Graph restore fabricated approval authority"
                )
        else:
            state = _verified_graph_store_state(temporary, campaign_id=campaign_id)
            _require_manifest_state(manifest, state)
        _publish_exclusive(
            temporary,
            destination_path,
            label="SQLite Graph restore destination",
        )
    except (
        ActionApprovalError,
        OSError,
        sqlite3.Error,
        ValidationError,
        ValueError,
        SQLiteGraphStoreError,
    ) as exc:
        if isinstance(exc, SQLiteGraphStoreError):
            raise
        raise SQLiteGraphStoreError("SQLite Graph backup restore failed") from exc
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _copy_sqlite_backup(source: Path, destination: Path, *, campaign_id: str) -> None:
    with _readonly_connection(source) as source_connection:
        _validate_schema(source_connection, campaign_id=campaign_id)
        target_connection = sqlite3.connect(
            destination,
            isolation_level=None,
            timeout=_BUSY_TIMEOUT_MS / 1_000,
        )
        try:
            target_connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
            target_connection.execute("PRAGMA synchronous = FULL")
            source_connection.backup(target_connection)
        finally:
            target_connection.close()
    _fsync_graph_file(destination)


def _verified_graph_store_state(
    path: Path,
    *,
    campaign_id: str,
) -> _VerifiedGraphStoreState:
    with _readonly_connection(path) as connection:
        _validate_schema(connection, campaign_id=campaign_id)
        events = _events_from_connection(connection, campaign_id=campaign_id)
        _require_exact_node_index(connection, campaign_id=campaign_id, events=events)
        projections = _verified_projections(
            connection,
            campaign_id=campaign_id,
            events=events,
        )
        snapshots, snapshot_head = _verified_snapshots(
            connection,
            campaign_id=campaign_id,
            projections=projections,
        )
        permits = _verified_action_permits(
            connection,
            campaign_id=campaign_id,
            snapshots=snapshots,
        )
        reservations = _verified_cleanup_reservations(
            connection,
            campaign_id=campaign_id,
            action_permits=permits,
        )
        cleanup_permits = _verified_cleanup_permits(
            connection,
            campaign_id=campaign_id,
            snapshots=snapshots,
            action_permits=permits,
            reservations=reservations,
        )
        approvals = _verified_action_approvals(
            connection,
            campaign_id=campaign_id,
        )
        approval_consumptions = _verified_approval_consumptions(
            connection,
            campaign_id=campaign_id,
            action_permits=permits,
            approvals=approvals,
            cleanup_reservations=reservations,
        )
        current_projection = projections[max(projections)]
        return _VerifiedGraphStoreState(
            event_count=len(events),
            event_log_head_digest=events[-1].event_digest if events else None,
            projection_revision=current_projection.revision,
            projection_digest=current_projection.projection_digest,
            snapshot_count=len(snapshots),
            snapshot_head_digest=snapshot_head,
            action_permit_count=len(permits),
            action_permit_head_digest=permits[-1].permit_digest if permits else None,
            cleanup_reservation_count=len(reservations),
            cleanup_reservation_head_digest=(
                reservations[-1].cleanup_reservation_digest if reservations else None
            ),
            cleanup_permit_count=len(cleanup_permits),
            cleanup_permit_head_digest=(
                cleanup_permits[-1].cleanup_permit_digest if cleanup_permits else None
            ),
            action_approval_count=len(approvals),
            action_approval_head_digest=(approvals[-1].approval_digest if approvals else None),
            approval_consumption_count=len(approval_consumptions),
            approval_consumption_head_digest=(
                approval_consumptions[-1].receipt_digest if approval_consumptions else None
            ),
        )


def _verified_v2_graph_store_state(
    path: Path,
    *,
    campaign_id: str,
) -> _VerifiedGraphStoreState:
    """Verify an exact legacy v2 store without mutating its backup source."""

    with _readonly_connection(path) as connection:
        _validate_schema_contract(
            connection,
            campaign_id=campaign_id,
            tables=_ACTION_PERMIT_TABLES,
            objects=_ACTION_PERMIT_SCHEMA_OBJECT_SQL,
            version=_ACTION_PERMIT_SCHEMA_VERSION,
            digest=_ACTION_PERMIT_SCHEMA_DIGEST,
        )
        events = _events_from_connection(connection, campaign_id=campaign_id)
        _require_exact_node_index(connection, campaign_id=campaign_id, events=events)
        projections = _verified_projections(
            connection,
            campaign_id=campaign_id,
            events=events,
        )
        snapshots, snapshot_head = _verified_snapshots(
            connection,
            campaign_id=campaign_id,
            projections=projections,
        )
        permits = _verified_action_permits(
            connection,
            campaign_id=campaign_id,
            snapshots=snapshots,
        )
        current_projection = projections[max(projections)]
        return _VerifiedGraphStoreState(
            event_count=len(events),
            event_log_head_digest=events[-1].event_digest if events else None,
            projection_revision=current_projection.revision,
            projection_digest=current_projection.projection_digest,
            snapshot_count=len(snapshots),
            snapshot_head_digest=snapshot_head,
            action_permit_count=len(permits),
            action_permit_head_digest=permits[-1].permit_digest if permits else None,
            cleanup_reservation_count=0,
            cleanup_reservation_head_digest=None,
            cleanup_permit_count=0,
            cleanup_permit_head_digest=None,
            action_approval_count=0,
            action_approval_head_digest=None,
            approval_consumption_count=0,
            approval_consumption_head_digest=None,
        )


def _verified_v3_graph_store_state(
    path: Path,
    *,
    campaign_id: str,
) -> _VerifiedGraphStoreState:
    """Verify an exact legacy v3 cleanup store without mutating its backup source."""

    with _readonly_connection(path) as connection:
        _validate_schema_contract(
            connection,
            campaign_id=campaign_id,
            tables=_CLEANUP_TABLES,
            objects=_CLEANUP_SCHEMA_OBJECT_SQL,
            version=_CLEANUP_SCHEMA_VERSION,
            digest=_CLEANUP_SCHEMA_DIGEST,
        )
        events = _events_from_connection(connection, campaign_id=campaign_id)
        _require_exact_node_index(connection, campaign_id=campaign_id, events=events)
        projections = _verified_projections(
            connection,
            campaign_id=campaign_id,
            events=events,
        )
        snapshots, snapshot_head = _verified_snapshots(
            connection,
            campaign_id=campaign_id,
            projections=projections,
        )
        permits = _verified_action_permits(
            connection,
            campaign_id=campaign_id,
            snapshots=snapshots,
        )
        reservations = _verified_cleanup_reservations(
            connection,
            campaign_id=campaign_id,
            action_permits=permits,
        )
        cleanup_permits = _verified_cleanup_permits(
            connection,
            campaign_id=campaign_id,
            snapshots=snapshots,
            action_permits=permits,
            reservations=reservations,
        )
        current_projection = projections[max(projections)]
        return _VerifiedGraphStoreState(
            event_count=len(events),
            event_log_head_digest=events[-1].event_digest if events else None,
            projection_revision=current_projection.revision,
            projection_digest=current_projection.projection_digest,
            snapshot_count=len(snapshots),
            snapshot_head_digest=snapshot_head,
            action_permit_count=len(permits),
            action_permit_head_digest=permits[-1].permit_digest if permits else None,
            cleanup_reservation_count=len(reservations),
            cleanup_reservation_head_digest=(
                reservations[-1].cleanup_reservation_digest if reservations else None
            ),
            cleanup_permit_count=len(cleanup_permits),
            cleanup_permit_head_digest=(
                cleanup_permits[-1].cleanup_permit_digest if cleanup_permits else None
            ),
            action_approval_count=0,
            action_approval_head_digest=None,
            approval_consumption_count=0,
            approval_consumption_head_digest=None,
        )


def _require_exact_node_index(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    events: tuple[GraphAdmissionEvent, ...],
) -> None:
    expected_nodes: dict[str, tuple[GraphNode, int]] = {}
    for event in events:
        if event.decision is not GraphAdmissionDecision.ADMITTED:
            continue
        for node in event.admitted_nodes:
            expected_nodes.setdefault(node.node_id, (node, event.sequence))
    node_rows = connection.execute("SELECT * FROM graph_nodes ORDER BY node_id").fetchall()
    stored_nodes = {
        cast(str, row["node_id"]): (
            _node_from_row(row, campaign_id=campaign_id),
            cast(int, row["admitted_sequence"]),
        )
        for row in node_rows
    }
    if stored_nodes != expected_nodes:
        raise SQLiteGraphStoreError(
            "SQLite Graph backup admitted-node index differs from its Event Log"
        )


def _verified_projections(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    events: tuple[GraphAdmissionEvent, ...],
) -> dict[int, GraphProjection]:
    projection_rows = connection.execute(
        "SELECT * FROM graph_projections ORDER BY revision"
    ).fetchall()
    if not projection_rows:
        raise SQLiteGraphStoreError("SQLite Graph backup has no genesis projection")
    projections: dict[int, GraphProjection] = {}
    for row in projection_rows:
        projection = _projection_from_row(row, campaign_id=campaign_id)
        if projection.revision > len(events):
            raise SQLiteGraphStoreError(
                "SQLite Graph backup Projection is ahead of its Event Log"
            )
        expected_projection = GraphProjector.project(
            campaign_id=campaign_id,
            events=events[: projection.revision],
        )
        if projection != expected_projection:
            raise SQLiteGraphStoreError(
                "SQLite Graph backup Projection differs from its Event Log prefix"
            )
        projections[projection.revision] = projection
    if 0 not in projections:
        raise SQLiteGraphStoreError("SQLite Graph backup has no genesis projection")
    return projections


def _verified_snapshots(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    projections: dict[int, GraphProjection],
) -> tuple[dict[str, GraphSnapshot], str | None]:
    snapshot_rows = connection.execute(
        "SELECT * FROM graph_snapshots ORDER BY ordinal"
    ).fetchall()
    snapshots: dict[str, GraphSnapshot] = {}
    previous_snapshot: str | None = None
    for ordinal, row in enumerate(snapshot_rows, start=1):
        if row["ordinal"] != ordinal:
            raise SQLiteGraphStoreError(
                "SQLite Graph backup Snapshot ordinals are not contiguous"
            )
        snapshot = _snapshot_from_row(row, campaign_id=campaign_id)
        if snapshot.previous_snapshot_digest != previous_snapshot:
            raise SQLiteGraphStoreError("SQLite Graph backup Snapshot chain is not contiguous")
        if projections.get(snapshot.revision) != snapshot.projection:
            raise SQLiteGraphStoreError(
                "SQLite Graph backup Snapshot differs from its published Projection"
            )
        snapshots[snapshot.snapshot_id] = snapshot
        previous_snapshot = snapshot.snapshot_digest
    return snapshots, previous_snapshot


def _verified_action_permits(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    snapshots: dict[str, GraphSnapshot],
) -> list[ActionPermit]:
    permit_rows = connection.execute(
        "SELECT * FROM graph_action_permits ORDER BY ordinal"
    ).fetchall()
    permits: list[ActionPermit] = []
    compiler_identity = _action_permit_writer_identity(connection)
    for ordinal, row in enumerate(permit_rows, start=1):
        if row["ordinal"] != ordinal:
            raise SQLiteGraphStoreError(
                "SQLite Graph backup ActionPermit ordinals are not contiguous"
            )
        permit = _action_permit_from_row(row, campaign_id=campaign_id)
        snapshot = snapshots.get(permit.snapshot.snapshot_id)
        if snapshot is None or permit.snapshot != graph_snapshot_ref(snapshot):
            raise SQLiteGraphStoreError(
                "SQLite Graph backup ActionPermit differs from its Snapshot"
            )
        if compiler_identity != (
            permit.compiler_id,
            permit.compiler_version,
            permit.compiler_digest,
        ):
            raise SQLiteGraphStoreError(
                "SQLite Graph backup ActionPermit differs from its compiler writer"
            )
        permits.append(permit)
    return permits


def _verified_action_approvals(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
) -> list[ActionApprovalEnvelope]:
    rows = connection.execute(
        "SELECT * FROM graph_action_approval_envelopes ORDER BY ordinal"
    ).fetchall()
    approvals: list[ActionApprovalEnvelope] = []
    for ordinal, row in enumerate(rows, start=1):
        if row["ordinal"] != ordinal:
            raise SQLiteGraphStoreError(
                "SQLite Graph backup Action approval ordinals are not contiguous"
            )
        approvals.append(_action_approval_from_row(row, campaign_id=campaign_id))
    return approvals


def _verified_approval_consumptions(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    action_permits: list[ActionPermit],
    approvals: list[ActionApprovalEnvelope],
    cleanup_reservations: list[ActionCleanupReservation],
) -> list[ActionApprovalConsumptionReceipt]:
    rows = connection.execute(
        "SELECT * FROM graph_action_approval_consumptions ORDER BY ordinal"
    ).fetchall()
    approval_by_id = {
        approval.approval_id: (ordinal, approval)
        for ordinal, approval in enumerate(approvals, start=1)
    }
    permit_by_id = {permit.permit_id: permit for permit in action_permits}
    reservation_by_permit = {
        reservation.source_action_permit_id: reservation
        for reservation in cleanup_reservations
    }
    receipts: list[ActionApprovalConsumptionReceipt] = []
    consumed_approval_ids: set[str] = set()
    for ordinal, row in enumerate(rows, start=1):
        if row["ordinal"] != ordinal:
            raise SQLiteGraphStoreError(
                "SQLite Graph backup approval consumption ordinals are not contiguous"
            )
        receipt = _approval_consumption_from_row(row, campaign_id=campaign_id)
        approval_entry = approval_by_id.get(receipt.approval.approval_id)
        permit = permit_by_id.get(receipt.action_permit.permit_id)
        reservation = reservation_by_permit.get(receipt.action_permit.permit_id)
        if (
            approval_entry is None
            or permit is None
            or approval_entry[0] != ordinal
            or approval_entry[1] != receipt.approval
            or permit != receipt.action_permit
            or receipt
            != build_action_approval_consumption_receipt(approval_entry[1], permit)
            or approval_entry[1].cleanup_required is not (reservation is not None)
        ):
            raise SQLiteGraphStoreError(
                "SQLite Graph backup approval receipt differs from source authority"
            )
        consumed_approval_ids.add(approval_entry[1].approval_id)
        receipts.append(receipt)
    if consumed_approval_ids != set(approval_by_id):
        raise SQLiteGraphStoreError("SQLite Graph backup approval authority is partially committed")
    return receipts


def _verified_cleanup_reservations(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    action_permits: list[ActionPermit],
) -> list[ActionCleanupReservation]:
    rows = connection.execute(
        "SELECT * FROM graph_action_cleanup_reservations ORDER BY ordinal"
    ).fetchall()
    actions = {permit.permit_id: permit for permit in action_permits}
    compiler_identity = _action_permit_writer_identity(connection)
    reservations: list[ActionCleanupReservation] = []
    for ordinal, row in enumerate(rows, start=1):
        if row["ordinal"] != ordinal:
            raise SQLiteGraphStoreError(
                "SQLite Graph backup cleanup reservation ordinals are not contiguous"
            )
        reservation = _cleanup_reservation_from_row(row, campaign_id=campaign_id)
        action = actions.get(reservation.source_action_permit_id)
        if (
            action is None
            or action.campaign_id != reservation.campaign_id
            or action.run_id != reservation.run_id
            or action.compiler_id != reservation.compiler_id
            or action.compiler_version != reservation.compiler_version
            or action.compiler_digest != reservation.compiler_digest
            or action.envelope_id != reservation.envelope_id
            or action.envelope_digest != reservation.envelope_digest
            or action.permit_digest != reservation.source_action_permit_digest
            or action.dispatch_id != reservation.source_action_dispatch_id
            or action.target_digest != reservation.target_digest
            or action.consumed_at != reservation.reserved_at
        ):
            raise SQLiteGraphStoreError(
                "SQLite Graph backup cleanup reservation differs from its ActionPermit"
            )
        if compiler_identity != (
            reservation.compiler_id,
            reservation.compiler_version,
            reservation.compiler_digest,
        ):
            raise SQLiteGraphStoreError(
                "SQLite Graph backup cleanup reservation differs from its compiler writer"
            )
        reservations.append(reservation)
    return reservations


def _verified_cleanup_permits(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    snapshots: dict[str, GraphSnapshot],
    action_permits: list[ActionPermit],
    reservations: list[ActionCleanupReservation],
) -> list[CleanupPermit]:
    rows = connection.execute(
        "SELECT * FROM graph_cleanup_permits ORDER BY ordinal"
    ).fetchall()
    actions = {permit.permit_id: permit for permit in action_permits}
    holds = {
        reservation.cleanup_reservation_id: reservation
        for reservation in reservations
    }
    compiler_identity = _action_permit_writer_identity(connection)
    permits: list[CleanupPermit] = []
    for ordinal, row in enumerate(rows, start=1):
        if row["ordinal"] != ordinal:
            raise SQLiteGraphStoreError(
                "SQLite Graph backup CleanupPermit ordinals are not contiguous"
            )
        permit = _cleanup_permit_from_row(row, campaign_id=campaign_id)
        snapshot = snapshots.get(permit.snapshot.snapshot_id)
        action = actions.get(permit.source_action_permit_id)
        hold = holds.get(permit.cleanup_reservation_id)
        if snapshot is None or permit.snapshot != graph_snapshot_ref(snapshot):
            raise SQLiteGraphStoreError(
                "SQLite Graph backup CleanupPermit differs from its Snapshot"
            )
        if (
            action is None
            or action.campaign_id != permit.campaign_id
            or action.run_id != permit.run_id
            or action.compiler_id != permit.compiler_id
            or action.compiler_version != permit.compiler_version
            or action.compiler_digest != permit.compiler_digest
            or action.envelope_id != permit.envelope_id
            or action.envelope_digest != permit.envelope_digest
            or action.permit_digest != permit.source_action_permit_digest
            or action.dispatch_id != permit.source_action_dispatch_id
            or action.target_digest != permit.target_digest
            or hold is None
            or hold.campaign_id != permit.campaign_id
            or hold.run_id != permit.run_id
            or hold.compiler_id != permit.compiler_id
            or hold.compiler_version != permit.compiler_version
            or hold.compiler_digest != permit.compiler_digest
            or hold.envelope_id != permit.envelope_id
            or hold.envelope_digest != permit.envelope_digest
            or hold.cleanup_reservation_digest != permit.cleanup_reservation_digest
            or hold.source_action_permit_id != permit.source_action_permit_id
            or hold.source_action_permit_digest != permit.source_action_permit_digest
            or hold.source_action_dispatch_id != permit.source_action_dispatch_id
            or hold.cleanup_capability != permit.capability
            or hold.target_digest != permit.target_digest
            or hold.cleanup_handler_digest != permit.cleanup_handler_digest
            or hold.cleanup_executor_digest != permit.cleanup_executor_digest
            or hold.reservation != permit.reservation
            or hold.reserved_at != action.consumed_at
            or permit.issued_at != permit.consumed_at
            or not hold.reserved_at <= permit.consumed_at < hold.claim_expires_at
            or permit.expires_at > hold.claim_expires_at
        ):
            raise SQLiteGraphStoreError(
                "SQLite Graph backup CleanupPermit differs from its source authority"
            )
        if compiler_identity != (
            permit.compiler_id,
            permit.compiler_version,
            permit.compiler_digest,
        ):
            raise SQLiteGraphStoreError(
                "SQLite Graph backup CleanupPermit differs from its compiler writer"
            )
        permits.append(permit)
    return permits


def _require_manifest_state(
    manifest: SQLiteGraphBackupManifest,
    state: _VerifiedGraphStoreState,
) -> None:
    if (
        manifest.schema_version != _SCHEMA_VERSION
        or manifest.schema_digest != _SCHEMA_DIGEST
        or manifest.event_count != state.event_count
        or manifest.event_log_head_digest != state.event_log_head_digest
        or manifest.projection_revision != state.projection_revision
        or manifest.projection_digest != state.projection_digest
        or manifest.snapshot_count != state.snapshot_count
        or manifest.snapshot_head_digest != state.snapshot_head_digest
        or manifest.action_permit_count != state.action_permit_count
        or manifest.action_permit_head_digest != state.action_permit_head_digest
        or manifest.cleanup_reservation_count != state.cleanup_reservation_count
        or manifest.cleanup_reservation_head_digest
        != state.cleanup_reservation_head_digest
        or manifest.cleanup_permit_count != state.cleanup_permit_count
        or manifest.cleanup_permit_head_digest != state.cleanup_permit_head_digest
        or manifest.action_approval_count != state.action_approval_count
        or manifest.action_approval_head_digest != state.action_approval_head_digest
        or manifest.approval_consumption_count != state.approval_consumption_count
        or manifest.approval_consumption_head_digest != state.approval_consumption_head_digest
    ):
        raise SQLiteGraphStoreError("SQLite Graph backup manifest differs from restored state")


def _require_cleanup_manifest_state(
    manifest: _SQLiteGraphBackupManifestV2,
    state: _VerifiedGraphStoreState,
) -> None:
    if (
        manifest.schema_version != _CLEANUP_SCHEMA_VERSION
        or manifest.schema_digest != _CLEANUP_SCHEMA_DIGEST
        or manifest.event_count != state.event_count
        or manifest.event_log_head_digest != state.event_log_head_digest
        or manifest.projection_revision != state.projection_revision
        or manifest.projection_digest != state.projection_digest
        or manifest.snapshot_count != state.snapshot_count
        or manifest.snapshot_head_digest != state.snapshot_head_digest
        or manifest.action_permit_count != state.action_permit_count
        or manifest.action_permit_head_digest != state.action_permit_head_digest
        or manifest.cleanup_reservation_count != state.cleanup_reservation_count
        or manifest.cleanup_reservation_head_digest != state.cleanup_reservation_head_digest
        or manifest.cleanup_permit_count != state.cleanup_permit_count
        or manifest.cleanup_permit_head_digest != state.cleanup_permit_head_digest
    ):
        raise SQLiteGraphStoreError(
            "legacy cleanup SQLite Graph backup manifest differs from restored state"
        )


def _require_legacy_manifest_state(
    manifest: _SQLiteGraphBackupManifestV1,
    state: _VerifiedGraphStoreState,
) -> None:
    if (
        manifest.schema_version != _ACTION_PERMIT_SCHEMA_VERSION
        or manifest.schema_digest != _ACTION_PERMIT_SCHEMA_DIGEST
        or manifest.event_count != state.event_count
        or manifest.event_log_head_digest != state.event_log_head_digest
        or manifest.projection_revision != state.projection_revision
        or manifest.projection_digest != state.projection_digest
        or manifest.snapshot_count != state.snapshot_count
        or manifest.snapshot_head_digest != state.snapshot_head_digest
        or manifest.action_permit_count != state.action_permit_count
        or manifest.action_permit_head_digest != state.action_permit_head_digest
    ):
        raise SQLiteGraphStoreError(
            "legacy SQLite Graph backup manifest differs from restored state"
        )


def _backup_manifest_bytes(
    manifest: (
        SQLiteGraphBackupManifest | _SQLiteGraphBackupManifestV2 | _SQLiteGraphBackupManifestV1
    ),
) -> bytes:
    return (
        canonical_graph_json(
            manifest.model_dump(mode="json", by_alias=True),
            label="SQLiteGraphBackupManifest",
            max_bytes=_MAX_GRAPH_BACKUP_MANIFEST_BYTES,
        )
        + b"\n"
    )


def _private_temporary_path(destination: Path) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    return Path(name)


def _write_private_temporary(destination: Path, content: bytes) -> Path:
    temporary = _private_temporary_path(destination)
    try:
        _write_existing_private_file(temporary, content)
    except BaseException:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise
    return temporary


def _write_existing_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOINHERIT", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_absent_leaf(path: Path, *, label: str) -> None:
    if path.exists() or path.is_symlink() or path.is_junction():
        raise SQLiteGraphStoreError(f"{label} path already exists")


def _publish_exclusive(source: Path, destination: Path, *, label: str) -> None:
    _require_absent_leaf(destination, label=label)
    parent_identity = destination.parent.lstat()
    published = False
    try:
        os.link(source, destination, follow_symlinks=False)
        published = True
        observed_parent = destination.parent.lstat()
        if (
            destination.parent.is_symlink()
            or destination.parent.is_junction()
            or (observed_parent.st_dev, observed_parent.st_ino)
            != (parent_identity.st_dev, parent_identity.st_ino)
        ):
            raise SQLiteGraphStoreError(f"{label} parent changed during publication")
        source.unlink()
        file_stat = destination.lstat()
        if (
            destination.is_symlink()
            or destination.is_junction()
            or not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_nlink != 1
        ):
            raise SQLiteGraphStoreError(f"{label} publication identity is invalid")
        _fsync_graph_directory(destination.parent)
        published = False
    except FileExistsError as exc:
        raise SQLiteGraphStoreError(f"{label} path already exists") from exc
    except BaseException:
        if published:
            with suppress(OSError):
                destination.unlink()
        raise


def _fsync_graph_file(path: Path) -> None:
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOINHERIT", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_graph_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _absolute_path(path: Path) -> Path:
    """Normalize lexical components without following a symlink leaf."""

    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _prepare_store_file(path: Path) -> tuple[bool, int]:
    _prepare_private_parent(path.parent)
    _reject_sidecar_links(path)
    created = False
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise SQLiteGraphStoreError("SQLite Graph Store path is not a regular file") from exc
    try:
        file_stat = os.fstat(descriptor)
        path_stat = path.lstat()
        if (
            path.is_symlink()
            or path.is_junction()
            or not stat.S_ISREG(file_stat.st_mode)
            or not stat.S_ISREG(path_stat.st_mode)
            or file_stat.st_nlink != 1
            or (file_stat.st_dev, file_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino)
        ):
            raise SQLiteGraphStoreError("SQLite Graph Store path is not a private regular file")
        if os.name == "posix":
            if file_stat.st_uid != os.geteuid():
                raise SQLiteGraphStoreError("SQLite Graph Store is not owned by this user")
            os.fchmod(descriptor, 0o600)
        return created, file_stat.st_size
    finally:
        os.close(descriptor)


def _prepare_private_parent(directory: Path) -> None:
    current = Path(directory.anchor)
    for component in directory.parts[1:]:
        current /= component
        try:
            component_stat = current.lstat()
        except FileNotFoundError:
            with suppress(FileExistsError):
                current.mkdir(mode=0o700)
            component_stat = current.lstat()
        if (
            current.is_symlink()
            or current.is_junction()
            or not stat.S_ISDIR(component_stat.st_mode)
        ):
            raise SQLiteGraphStoreError(
                "SQLite Graph Store parent path contains a non-directory component"
            )
    try:
        directory_stat = directory.lstat()
    except OSError as exc:
        raise SQLiteGraphStoreError("SQLite Graph Store parent changed during validation") from exc
    if (
        directory.is_symlink()
        or directory.is_junction()
        or not stat.S_ISDIR(directory_stat.st_mode)
    ):
        raise SQLiteGraphStoreError("SQLite Graph Store parent is not a regular directory")
    if os.name == "posix":
        if directory_stat.st_uid != os.geteuid():
            raise SQLiteGraphStoreError("SQLite Graph Store parent is not owned by this user")
        if stat.S_IMODE(directory_stat.st_mode) & 0o077:
            raise SQLiteGraphStoreError("SQLite Graph Store parent must be owner-only")


def _reject_sidecar_links(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not sidecar.exists() and not sidecar.is_symlink() and not sidecar.is_junction():
            continue
        try:
            sidecar_stat = sidecar.lstat()
        except OSError as exc:
            raise SQLiteGraphStoreError(
                "SQLite Graph Store sidecar changed during validation"
            ) from exc
        if (
            sidecar.is_symlink()
            or sidecar.is_junction()
            or not stat.S_ISREG(sidecar_stat.st_mode)
            or sidecar_stat.st_nlink != 1
        ):
            raise SQLiteGraphStoreError("SQLite Graph Store sidecar is not a private regular file")
        if os.name == "posix" and sidecar_stat.st_uid != os.geteuid():
            raise SQLiteGraphStoreError("SQLite Graph Store sidecar is not owned by this user")


def _file_identity(path: Path) -> tuple[tuple[int, int], tuple[int, int]]:
    parent_stat = path.parent.lstat()
    file_stat = path.lstat()
    if (
        path.parent.is_symlink()
        or path.parent.is_junction()
        or path.is_symlink()
        or path.is_junction()
        or not stat.S_ISDIR(parent_stat.st_mode)
        or not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_nlink != 1
    ):
        raise SQLiteGraphStoreError("SQLite Graph Store path identity is invalid")
    return (
        (parent_stat.st_dev, parent_stat.st_ino),
        (file_stat.st_dev, file_stat.st_ino),
    )


def _initialize(path: Path, campaign_id: str) -> None:
    created, file_size = _prepare_store_file(path)
    initialize_empty_file = created or file_size == 0
    try:
        connection = _open_write_connection(path)
        try:
            if initialize_empty_file:
                journal_mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
                if journal_mode is None or str(journal_mode[0]).lower() != "delete":
                    raise SQLiteGraphStoreError("SQLite Graph Store requires DELETE journal mode")
            connection.execute("BEGIN IMMEDIATE")
            tables = _application_tables(connection)
            if not tables:
                if not initialize_empty_file:
                    raise SQLiteGraphStoreError("existing SQLite Graph Store has no trusted schema")
                for statement in _SCHEMA_OBJECT_SQL.values():
                    connection.execute(statement)
                connection.executemany(
                    "INSERT INTO graph_store_metadata (key, value) VALUES (?, ?)",
                    (
                        ("schema_version", str(_SCHEMA_VERSION)),
                        ("schema_digest", _SCHEMA_DIGEST),
                        ("campaign_id", campaign_id),
                    ),
                )
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                genesis = GraphProjector.project(campaign_id=campaign_id, events=())
                connection.execute(
                    """
                    INSERT INTO graph_projections (
                        revision, event_log_head_digest, projection_id,
                        projection_digest, projection_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        genesis.revision,
                        genesis.event_log_head_digest,
                        genesis.projection_id,
                        genesis.projection_digest,
                        sqlite3.Binary(_projection_bytes(genesis)),
                    ),
                )
            elif tables == _LEGACY_TABLES:
                _validate_schema_contract(
                    connection,
                    campaign_id=campaign_id,
                    tables=_LEGACY_TABLES,
                    objects=_LEGACY_SCHEMA_OBJECT_SQL,
                    version=_LEGACY_SCHEMA_VERSION,
                    digest=_LEGACY_SCHEMA_DIGEST,
                )
                _migrate_legacy_schema(connection)
            elif tables == _ACTION_PERMIT_TABLES:
                _validate_schema_contract(
                    connection,
                    campaign_id=campaign_id,
                    tables=_ACTION_PERMIT_TABLES,
                    objects=_ACTION_PERMIT_SCHEMA_OBJECT_SQL,
                    version=_ACTION_PERMIT_SCHEMA_VERSION,
                    digest=_ACTION_PERMIT_SCHEMA_DIGEST,
                )
                _migrate_action_permit_schema(connection)
            elif tables == _CLEANUP_TABLES:
                _validate_schema_contract(
                    connection,
                    campaign_id=campaign_id,
                    tables=_CLEANUP_TABLES,
                    objects=_CLEANUP_SCHEMA_OBJECT_SQL,
                    version=_CLEANUP_SCHEMA_VERSION,
                    digest=_CLEANUP_SCHEMA_DIGEST,
                )
                _migrate_cleanup_schema(connection)
            _validate_schema(connection, campaign_id=campaign_id)
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise SQLiteGraphStoreError("SQLite Graph Store initialization failed") from exc


@contextmanager
def _write_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    connection = _open_write_connection(path)
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


@contextmanager
def _readonly_connection(path: Path) -> Iterator[sqlite3.Connection]:
    identity = _file_identity(path)
    connection = sqlite3.connect(
        f"{path.as_uri()}?mode=ro",
        uri=True,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    if _file_identity(path) != identity:
        connection.close()
        raise SQLiteGraphStoreError("SQLite Graph Store changed while it was opened")
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA query_only = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
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


def _open_write_connection(path: Path) -> sqlite3.Connection:
    identity = _file_identity(path)
    connection = sqlite3.connect(
        path,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    if _file_identity(path) != identity:
        connection.close()
        raise SQLiteGraphStoreError("SQLite Graph Store changed while it was opened")
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA trusted_schema = OFF")
    return connection


def _application_tables(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute(
        """
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        """
    ).fetchall()
    return {cast(str, row["name"]) for row in rows}


def _validate_schema(connection: sqlite3.Connection, *, campaign_id: str) -> None:
    _validate_schema_contract(
        connection,
        campaign_id=campaign_id,
        tables=_TABLES,
        objects=_SCHEMA_OBJECT_SQL,
        version=_SCHEMA_VERSION,
        digest=_SCHEMA_DIGEST,
    )


def _validate_schema_contract(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    tables: frozenset[str],
    objects: dict[tuple[str, str], str],
    version: int,
    digest: str,
) -> None:
    if _application_tables(connection) != tables:
        raise SQLiteGraphStoreError("SQLite Graph Store schema is invalid")
    metadata_rows = connection.execute(
        "SELECT key, value FROM graph_store_metadata ORDER BY key"
    ).fetchall()
    metadata = {cast(str, row["key"]): cast(str, row["value"]) for row in metadata_rows}
    if metadata != {
        "campaign_id": campaign_id,
        "schema_digest": digest,
        "schema_version": str(version),
    }:
        raise SQLiteGraphStoreError("SQLite Graph Store metadata or Campaign identity differs")
    user_version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
    application_id = cast(int, connection.execute("PRAGMA application_id").fetchone()[0])
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    trusted_schema = connection.execute("PRAGMA trusted_schema").fetchone()
    if (
        user_version != version
        or application_id != _APPLICATION_ID
        or journal_mode is None
        or str(journal_mode[0]).lower() != "delete"
        or foreign_keys is None
        or foreign_keys[0] != 1
        or trusted_schema is None
        or trusted_schema[0] != 0
    ):
        raise SQLiteGraphStoreError("SQLite Graph Store version or connection policy is invalid")
    placeholders = ", ".join("?" for _ in tables)
    rows = connection.execute(
        f"""
        SELECT type, name, sql FROM sqlite_master
        WHERE sql IS NOT NULL
          AND type IN ('table', 'index', 'trigger')
          AND (name IN ({placeholders}) OR tbl_name IN ({placeholders}))
        """,
        (*sorted(tables), *sorted(tables)),
    ).fetchall()
    actual = {
        (cast(str, row["type"]), cast(str, row["name"])): _normalize_schema_sql(
            cast(str, row["sql"])
        )
        for row in rows
    }
    expected = {key: _normalize_schema_sql(statement) for key, statement in objects.items()}
    if actual != expected:
        raise SQLiteGraphStoreError("SQLite Graph Store schema fingerprint is invalid")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise SQLiteGraphStoreError("SQLite Graph Store contains orphaned records")
    quick_check = connection.execute("PRAGMA quick_check").fetchall()
    if len(quick_check) != 1 or quick_check[0][0] != "ok":
        raise SQLiteGraphStoreError("SQLite Graph Store integrity check failed")


def _migrate_legacy_schema(connection: sqlite3.Connection) -> None:
    """Upgrade the exact append-only v1 store to the current authority schema."""

    _migrate_schema(connection, previous_objects=_LEGACY_SCHEMA_OBJECT_SQL)


def _migrate_action_permit_schema(connection: sqlite3.Connection) -> None:
    """Upgrade the exact v2 ActionPermit store to the current authority schema."""

    _migrate_schema(connection, previous_objects=_ACTION_PERMIT_SCHEMA_OBJECT_SQL)


def _migrate_cleanup_schema(connection: sqlite3.Connection) -> None:
    """Upgrade the exact v3 cleanup store without fabricating approval authority."""

    _migrate_schema(connection, previous_objects=_CLEANUP_SCHEMA_OBJECT_SQL)


def _migrate_schema(
    connection: sqlite3.Connection,
    *,
    previous_objects: dict[tuple[str, str], str],
) -> None:
    """Add only current authority objects and rotate immutable metadata exactly."""

    new_keys = _SCHEMA_OBJECT_SQL.keys() - previous_objects.keys()
    for key, statement in _SCHEMA_OBJECT_SQL.items():
        if key in new_keys:
            connection.execute(statement)
    metadata_triggers = _immutable_triggers("graph_store_metadata", "key")
    for _, trigger_name in metadata_triggers:
        connection.execute(f"DROP TRIGGER {trigger_name}")
    connection.execute(
        "UPDATE graph_store_metadata SET value = ? WHERE key = 'schema_version'",
        (str(_SCHEMA_VERSION),),
    )
    connection.execute(
        "UPDATE graph_store_metadata SET value = ? WHERE key = 'schema_digest'",
        (_SCHEMA_DIGEST,),
    )
    for statement in metadata_triggers.values():
        connection.execute(statement)
    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")


def _pin_writer(
    connection: sqlite3.Connection,
    *,
    writer_kind: str,
    writer_id: str,
    writer_digest: str,
) -> None:
    existing = _writer_identity(connection, writer_kind)
    if existing is None:
        connection.execute(
            """
            INSERT INTO graph_store_writers (
                writer_kind, writer_id, writer_digest
            ) VALUES (?, ?, ?)
            """,
            (writer_kind, writer_id, writer_digest),
        )
        return
    if existing != (writer_id, writer_digest):
        raise SQLiteGraphStoreError(
            f"SQLite Graph Store {writer_kind} writer identity is already pinned"
        )


def _writer_identity(
    connection: sqlite3.Connection,
    writer_kind: str,
) -> tuple[str, str] | None:
    row = connection.execute(
        """
        SELECT writer_id, writer_digest FROM graph_store_writers
        WHERE writer_kind = ?
        """,
        (writer_kind,),
    ).fetchone()
    if row is None:
        return None
    return cast(str, row["writer_id"]), cast(str, row["writer_digest"])


def _pin_action_permit_writer(
    connection: sqlite3.Connection,
    identity: tuple[str, str, str],
) -> None:
    existing = _action_permit_writer_identity(connection)
    if existing is None:
        connection.execute(
            """
            INSERT INTO graph_action_permit_writers (
                singleton, compiler_id, compiler_version, compiler_digest
            ) VALUES (1, ?, ?, ?)
            """,
            identity,
        )
        return
    if existing != identity:
        raise SQLiteGraphStoreError(
            "SQLite Graph Store ActionPermit compiler identity is already pinned"
        )


def _action_permit_writer_identity(
    connection: sqlite3.Connection,
) -> tuple[str, str, str] | None:
    row = connection.execute(
        """
        SELECT compiler_id, compiler_version, compiler_digest
        FROM graph_action_permit_writers
        WHERE singleton = 1
        """
    ).fetchone()
    if row is None:
        return None
    return (
        cast(str, row["compiler_id"]),
        cast(str, row["compiler_version"]),
        cast(str, row["compiler_digest"]),
    )


def _current_projection(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
) -> GraphProjection:
    row = connection.execute(
        "SELECT * FROM graph_projections ORDER BY revision DESC LIMIT 1"
    ).fetchone()
    if row is None:
        raise GraphProjectionError("SQLite Graph Store has no genesis projection")
    return _projection_from_row(row, campaign_id=campaign_id)


def _events_from_connection(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
) -> tuple[GraphAdmissionEvent, ...]:
    rows = connection.execute("SELECT * FROM graph_events ORDER BY sequence").fetchall()
    events = tuple(_event_from_row(row, campaign_id=campaign_id) for row in rows)
    _require_event_chain(events, campaign_id=campaign_id)
    return events


def _snapshot_head_digest(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT snapshot_digest FROM graph_snapshots ORDER BY ordinal DESC LIMIT 1"
    ).fetchone()
    return cast(str, row["snapshot_digest"]) if row else None


def _require_latest_action_snapshot(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    proposal: ActionProposal,
    decision: GraphDecision,
) -> None:
    row = connection.execute(
        "SELECT * FROM graph_snapshots WHERE snapshot_id = ?",
        (decision.snapshot.snapshot_id,),
    ).fetchone()
    if row is None:
        raise ActionPermitError("ActionPermit Graph Snapshot was not found")
    snapshot = _snapshot_from_row(row, campaign_id=campaign_id)
    if (
        snapshot.snapshot_id != decision.snapshot.snapshot_id
        or snapshot.snapshot_digest != decision.snapshot.snapshot_digest
        or snapshot.campaign_id != decision.snapshot.campaign_id
        or snapshot.graph_schema_version != decision.snapshot.graph_schema_version
        or snapshot.revision != decision.snapshot.revision
        or snapshot.event_log_head_digest != decision.snapshot.event_log_head_digest
        or snapshot.projection_digest != decision.snapshot.projection_digest
        or proposal.snapshot != decision.snapshot
    ):
        raise ActionPermitError("ActionPermit Graph Snapshot binding differs")
    if decision.created_at < snapshot.created_at or proposal.created_at < decision.created_at:
        raise ActionPermitError("Action authority timeline predates its Graph Snapshot")
    current = _current_projection(connection, campaign_id=campaign_id)
    events = _events_from_connection(connection, campaign_id=campaign_id)
    latest = GraphProjector.project(campaign_id=campaign_id, events=events)
    if current.projection_digest != latest.projection_digest:
        raise ActionPermitStaleDecision(
            "Graph projection recovery is required before ActionPermit dispatch"
        )
    observed = (
        snapshot.revision,
        snapshot.event_log_head_digest,
        snapshot.projection_id,
        snapshot.projection_digest,
    )
    expected = (
        latest.revision,
        latest.event_log_head_digest,
        latest.projection_id,
        latest.projection_digest,
    )
    if observed != expected:
        raise ActionPermitStaleDecision("Graph changed before the ActionPermit dispatch claim")


def _require_latest_cleanup_snapshot(
    connection: sqlite3.Connection,
    *,
    campaign_id: str,
    request: CleanupRequest,
    decision: GraphDecision,
) -> None:
    row = connection.execute(
        "SELECT * FROM graph_snapshots WHERE snapshot_id = ?",
        (decision.snapshot.snapshot_id,),
    ).fetchone()
    if row is None:
        raise CleanupPermitError("CleanupPermit Graph Snapshot was not found")
    snapshot = _snapshot_from_row(row, campaign_id=campaign_id)
    if (
        snapshot.snapshot_id != decision.snapshot.snapshot_id
        or snapshot.snapshot_digest != decision.snapshot.snapshot_digest
        or snapshot.campaign_id != decision.snapshot.campaign_id
        or snapshot.graph_schema_version != decision.snapshot.graph_schema_version
        or snapshot.revision != decision.snapshot.revision
        or snapshot.event_log_head_digest != decision.snapshot.event_log_head_digest
        or snapshot.projection_digest != decision.snapshot.projection_digest
        or request.snapshot != decision.snapshot
    ):
        raise CleanupPermitError("CleanupPermit Graph Snapshot binding differs")
    if decision.created_at < snapshot.created_at or request.created_at < decision.created_at:
        raise CleanupPermitError("cleanup authority timeline predates its Graph Snapshot")
    current = _current_projection(connection, campaign_id=campaign_id)
    events = _events_from_connection(connection, campaign_id=campaign_id)
    latest = GraphProjector.project(campaign_id=campaign_id, events=events)
    if current.projection_digest != latest.projection_digest:
        raise CleanupPermitStaleDecision(
            "Graph projection recovery is required before CleanupPermit dispatch"
        )
    observed = (
        snapshot.revision,
        snapshot.event_log_head_digest,
        snapshot.projection_id,
        snapshot.projection_digest,
    )
    expected = (
        latest.revision,
        latest.event_log_head_digest,
        latest.projection_id,
        latest.projection_digest,
    )
    if observed != expected:
        raise CleanupPermitStaleDecision("Graph changed before the CleanupPermit claim")


def _require_aggregate_action_budget(
    connection: sqlite3.Connection,
    *,
    envelope: MissionEnvelope,
    new_reservations: tuple[ActionBudgetReservation, ...],
    evaluated_at: datetime,
    error_type: type[RuntimeError],
) -> None:
    action_rows = connection.execute(
        """
        SELECT * FROM graph_action_permits
        WHERE envelope_id = ?
        ORDER BY ordinal
        """,
        (envelope.envelope_id,),
    ).fetchall()
    hold_rows = connection.execute(
        """
        SELECT * FROM graph_action_cleanup_reservations
        WHERE envelope_id = ?
        ORDER BY ordinal
        """,
        (envelope.envelope_id,),
    ).fetchall()
    cleanup_rows = connection.execute(
        """
        SELECT * FROM graph_cleanup_permits
        WHERE envelope_id = ?
        ORDER BY ordinal
        """,
        (envelope.envelope_id,),
    ).fetchall()
    actions = tuple(
        _action_permit_from_row(row, campaign_id=envelope.campaign_id)
        for row in action_rows
    )
    holds = tuple(
        _cleanup_reservation_from_row(row, campaign_id=envelope.campaign_id)
        for row in hold_rows
    )
    cleanups = tuple(
        _cleanup_permit_from_row(row, campaign_id=envelope.campaign_id)
        for row in cleanup_rows
    )
    if (
        any(item.envelope_digest != envelope.envelope_digest for item in actions)
        or any(item.envelope_digest != envelope.envelope_digest for item in holds)
        or any(item.envelope_digest != envelope.envelope_digest for item in cleanups)
    ):
        raise ActionPermitConflict("MissionEnvelope identity has equivocated")
    used_calls = len(actions) + len(holds)
    used_units = sum(item.reservation.request_units for item in actions) + sum(
        item.reservation.request_units for item in holds
    )
    used_cost = sum(item.reservation.cost_microusd for item in actions) + sum(
        item.reservation.cost_microusd for item in holds
    )
    new_calls = sum(item.tool_calls for item in new_reservations)
    new_units = sum(item.request_units for item in new_reservations)
    new_cost = sum(item.cost_microusd for item in new_reservations)
    if (
        used_calls + new_calls > envelope.budget.tool_call_limit
        or used_units + new_units > envelope.budget.request_unit_limit
        or used_cost + new_cost > envelope.budget.cost_limit_microusd
    ):
        raise error_type("MissionEnvelope durable Action plus cleanup budget is exhausted")
    window_seconds = envelope.budget.rolling_window_seconds
    window_limit = envelope.budget.rolling_request_unit_limit
    if window_seconds is None or window_limit is None:
        return
    window_start = evaluated_at - timedelta(seconds=window_seconds)
    cleanup_by_reservation = {
        permit.cleanup_reservation_id: permit for permit in cleanups
    }
    window_units = sum(
        permit.reservation.request_units
        for permit in actions
        if permit.consumed_at > window_start
    ) + sum(
        hold.reservation.request_units
        for hold in holds
        if (
            hold.cleanup_reservation_id not in cleanup_by_reservation
            or cleanup_by_reservation[hold.cleanup_reservation_id].consumed_at > window_start
        )
    )
    if window_units + new_units > window_limit:
        raise error_type("MissionEnvelope rolling Action plus cleanup rate is exhausted")


def _require_exact_action_permit_retry(
    permit: ActionPermit,
    *,
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
    capability: RegisteredActionCapability,
) -> None:
    if (
        permit.campaign_id != envelope.campaign_id
        or permit.run_id != envelope.run_id
        or permit.compiler_id != envelope.compiler_id
        or permit.compiler_version != envelope.compiler_version
        or permit.compiler_digest != envelope.compiler_digest
        or permit.envelope_id != envelope.envelope_id
        or permit.envelope_digest != envelope.envelope_digest
        or permit.proposal_id != proposal.proposal_id
        or permit.proposal_digest != proposal.proposal_digest
        or permit.decision_id != decision.decision_id
        or permit.decision_digest != decision.decision_digest
        or permit.snapshot != decision.snapshot
        or permit.capability != capability.reference()
        or permit.target_digest != proposal.target_digest
        or permit.request_id != proposal.request_id
        or permit.request_digest != proposal.request_digest
        or permit.normalized_parameters_digest != proposal.normalized_parameters_digest
        or permit.reservation != proposal.reservation
    ):
        raise ActionPermitConflict("ActionPermit exact retry differs from stored authority")


def _require_exact_cleanup_reservation_retry(
    reservation: ActionCleanupReservation,
    *,
    envelope: MissionEnvelope,
    action_permit: ActionPermit,
    request: ActionCleanupReservationRequest,
    cleanup_capability: RegisteredActionCapability,
) -> None:
    expected = build_action_cleanup_reservation(
        envelope,
        action_permit,
        request,
        evaluated_at=action_permit.consumed_at,
    )
    if (
        reservation != expected
        or reservation.cleanup_capability != cleanup_capability.reference()
    ):
        raise CleanupPermitConflict(
            "cleanup reservation exact retry differs from stored authority"
        )


def _require_exact_cleanup_permit_retry(
    permit: CleanupPermit,
    *,
    envelope: MissionEnvelope,
    request: CleanupRequest,
    decision: GraphDecision,
    capability: RegisteredActionCapability,
) -> None:
    if (
        permit.campaign_id != envelope.campaign_id
        or permit.run_id != envelope.run_id
        or permit.compiler_id != envelope.compiler_id
        or permit.compiler_version != envelope.compiler_version
        or permit.compiler_digest != envelope.compiler_digest
        or permit.envelope_id != envelope.envelope_id
        or permit.envelope_digest != envelope.envelope_digest
        or permit.cleanup_reservation_id != request.cleanup_reservation_id
        or permit.cleanup_reservation_digest != request.cleanup_reservation_digest
        or permit.cleanup_request_id != request.cleanup_request_id
        or permit.cleanup_request_digest != request.cleanup_request_digest
        or permit.source_action_permit_id != request.source_action_permit_id
        or permit.source_action_permit_digest != request.source_action_permit_digest
        or permit.source_action_dispatch_id != request.source_action_dispatch_id
        or permit.source_outcome_id != request.source_outcome_id
        or permit.source_outcome_digest != request.source_outcome_digest
        or permit.source_run_root_digest != request.source_run_root_digest
        or permit.source_terminal_event_digest != request.source_terminal_event_digest
        or permit.source_gateway_outcome_digest != request.source_gateway_outcome_digest
        or permit.decision_id != decision.decision_id
        or permit.decision_digest != decision.decision_digest
        or permit.snapshot != decision.snapshot
        or permit.cleanup_handler_digest != request.cleanup_handler_digest
        or permit.cleanup_executor_digest != request.cleanup_executor_digest
        or permit.cleanup_plan_digest != request.cleanup_plan_digest
        or permit.capability != capability.reference()
        or permit.target_digest != request.target_digest
        or permit.request_id != request.request_id
        or permit.request_digest != request.request_digest
        or permit.normalized_parameters_digest != request.normalized_parameters_digest
        or permit.reservation != request.reservation
    ):
        raise CleanupPermitConflict("CleanupPermit exact retry differs from stored authority")


def _insert_action_permit(connection: sqlite3.Connection, permit: ActionPermit) -> None:
    ordinal_row = connection.execute(
        "SELECT COALESCE(MAX(ordinal), 0) + 1 AS next_ordinal FROM graph_action_permits"
    ).fetchone()
    assert ordinal_row is not None
    connection.execute(
        """
        INSERT INTO graph_action_permits (
            ordinal, permit_id, permit_digest, dispatch_id,
            envelope_id, envelope_digest, proposal_id,
            proposal_digest, decision_id, decision_digest,
            snapshot_id, snapshot_digest, revision,
            event_log_head_digest, projection_digest,
            request_id, request_digest, request_units,
            cost_microusd, issued_at, consumed_at, expires_at,
            permit_json
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            cast(int, ordinal_row["next_ordinal"]),
            permit.permit_id,
            permit.permit_digest,
            permit.dispatch_id,
            permit.envelope_id,
            permit.envelope_digest,
            permit.proposal_id,
            permit.proposal_digest,
            permit.decision_id,
            permit.decision_digest,
            permit.snapshot.snapshot_id,
            permit.snapshot.snapshot_digest,
            permit.snapshot.revision,
            permit.snapshot.event_log_head_digest,
            permit.snapshot.projection_digest,
            permit.request_id,
            permit.request_digest,
            permit.reservation.request_units,
            permit.reservation.cost_microusd,
            permit.issued_at.isoformat(),
            permit.consumed_at.isoformat(),
            permit.expires_at.isoformat(),
            sqlite3.Binary(_action_permit_bytes(permit)),
        ),
    )


def _insert_action_approval(
    connection: sqlite3.Connection,
    approval: ActionApprovalEnvelope,
) -> None:
    ordinal_row = connection.execute(
        "SELECT COALESCE(MAX(ordinal), 0) + 1 AS next_ordinal FROM graph_action_approval_envelopes"
    ).fetchone()
    assert ordinal_row is not None
    proposal = approval.proposal
    connection.execute(
        """
        INSERT INTO graph_action_approval_envelopes (
            ordinal, approval_id, approval_digest, campaign_id, run_id,
            envelope_id, envelope_digest, issuer_authority_id,
            issuer_authority_digest, capability_id, capability_version,
            capability_digest, release_id, release_digest,
            proposal_id, proposal_digest, target_digest,
            request_id, request_digest, normalized_parameters_digest,
            risk_tier, request_units, cost_microusd,
            approved_at, not_before, expires_at, approval_json
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            cast(int, ordinal_row["next_ordinal"]),
            approval.approval_id,
            approval.approval_digest,
            approval.campaign_id,
            approval.run_id,
            approval.mission_envelope.envelope_id,
            approval.mission_envelope.envelope_digest,
            approval.issuer.authority_id,
            approval.issuer.authority_digest,
            approval.release.capability_id,
            approval.release.capability_version,
            approval.release.capability_digest,
            approval.release.release_id,
            approval.release.release_digest,
            proposal.proposal_id,
            proposal.proposal_digest,
            proposal.target_digest,
            proposal.request_id,
            proposal.request_digest,
            proposal.normalized_parameters_digest,
            proposal.risk_tier.name,
            proposal.reservation.request_units,
            proposal.reservation.cost_microusd,
            approval.approved_at.isoformat(),
            approval.not_before.isoformat(),
            approval.expires_at.isoformat(),
            sqlite3.Binary(_action_approval_bytes(approval)),
        ),
    )


def _insert_approval_consumption(
    connection: sqlite3.Connection,
    receipt: ActionApprovalConsumptionReceipt,
) -> None:
    ordinal_row = connection.execute(
        "SELECT COALESCE(MAX(ordinal), 0) + 1 AS next_ordinal "
        "FROM graph_action_approval_consumptions"
    ).fetchone()
    assert ordinal_row is not None
    connection.execute(
        """
        INSERT INTO graph_action_approval_consumptions (
            ordinal, receipt_id, receipt_digest, approval_id, approval_digest,
            permit_id, permit_digest, dispatch_id, proposal_id, proposal_digest,
            request_id, request_digest, normalized_parameters_digest,
            consumed_at, receipt_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cast(int, ordinal_row["next_ordinal"]),
            receipt.receipt_id,
            receipt.receipt_digest,
            receipt.approval.approval_id,
            receipt.approval.approval_digest,
            receipt.action_permit.permit_id,
            receipt.action_permit.permit_digest,
            receipt.dispatch_id,
            receipt.proposal_id,
            receipt.proposal_digest,
            receipt.request_id,
            receipt.request_digest,
            receipt.normalized_parameters_digest,
            receipt.action_permit.consumed_at.isoformat(),
            sqlite3.Binary(_approval_consumption_bytes(receipt)),
        ),
    )


def _insert_cleanup_reservation(
    connection: sqlite3.Connection,
    reservation: ActionCleanupReservation,
) -> None:
    ordinal_row = connection.execute(
        "SELECT COALESCE(MAX(ordinal), 0) + 1 AS next_ordinal "
        "FROM graph_action_cleanup_reservations"
    ).fetchone()
    assert ordinal_row is not None
    connection.execute(
        """
        INSERT INTO graph_action_cleanup_reservations (
            ordinal, cleanup_reservation_id, cleanup_reservation_digest,
            reservation_request_id, reservation_request_digest,
            source_action_permit_id, source_action_permit_digest,
            source_action_dispatch_id, envelope_id, envelope_digest,
            cleanup_capability_digest, target_digest,
            cleanup_handler_digest, cleanup_executor_digest,
            tool_calls, request_units, cost_microusd, reserved_at, claim_expires_at,
            reservation_json
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            cast(int, ordinal_row["next_ordinal"]),
            reservation.cleanup_reservation_id,
            reservation.cleanup_reservation_digest,
            reservation.reservation_request_id,
            reservation.reservation_request_digest,
            reservation.source_action_permit_id,
            reservation.source_action_permit_digest,
            reservation.source_action_dispatch_id,
            reservation.envelope_id,
            reservation.envelope_digest,
            reservation.cleanup_capability.capability_digest,
            reservation.target_digest,
            reservation.cleanup_handler_digest,
            reservation.cleanup_executor_digest,
            reservation.reservation.tool_calls,
            reservation.reservation.request_units,
            reservation.reservation.cost_microusd,
            reservation.reserved_at.isoformat(),
            reservation.claim_expires_at.isoformat(),
            sqlite3.Binary(_cleanup_reservation_bytes(reservation)),
        ),
    )


def _insert_cleanup_permit(
    connection: sqlite3.Connection,
    permit: CleanupPermit,
) -> None:
    ordinal_row = connection.execute(
        "SELECT COALESCE(MAX(ordinal), 0) + 1 AS next_ordinal FROM graph_cleanup_permits"
    ).fetchone()
    assert ordinal_row is not None
    connection.execute(
        """
        INSERT INTO graph_cleanup_permits (
            ordinal, cleanup_permit_id, cleanup_permit_digest,
            cleanup_dispatch_id, cleanup_reservation_id,
            cleanup_reservation_digest, source_action_permit_id,
            source_action_permit_digest, envelope_id, envelope_digest,
            cleanup_request_id, cleanup_request_digest,
            decision_id, decision_digest, snapshot_id, snapshot_digest,
            revision, event_log_head_digest, projection_digest,
            request_id, request_digest, cleanup_capability_digest,
            target_digest, cleanup_handler_digest, cleanup_executor_digest,
            cleanup_plan_digest, issued_at, consumed_at, expires_at,
            permit_json
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            cast(int, ordinal_row["next_ordinal"]),
            permit.cleanup_permit_id,
            permit.cleanup_permit_digest,
            permit.cleanup_dispatch_id,
            permit.cleanup_reservation_id,
            permit.cleanup_reservation_digest,
            permit.source_action_permit_id,
            permit.source_action_permit_digest,
            permit.envelope_id,
            permit.envelope_digest,
            permit.cleanup_request_id,
            permit.cleanup_request_digest,
            permit.decision_id,
            permit.decision_digest,
            permit.snapshot.snapshot_id,
            permit.snapshot.snapshot_digest,
            permit.snapshot.revision,
            permit.snapshot.event_log_head_digest,
            permit.snapshot.projection_digest,
            permit.request_id,
            permit.request_digest,
            permit.capability.capability_digest,
            permit.target_digest,
            permit.cleanup_handler_digest,
            permit.cleanup_executor_digest,
            permit.cleanup_plan_digest,
            permit.issued_at.isoformat(),
            permit.consumed_at.isoformat(),
            permit.expires_at.isoformat(),
            sqlite3.Binary(_cleanup_permit_bytes(permit)),
        ),
    )


def _event_bytes(event: GraphAdmissionEvent) -> bytes:
    return canonical_graph_json(
        event.model_dump(mode="json", by_alias=True),
        label="GraphAdmissionEvent",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _node_bytes(node: GraphNode) -> bytes:
    return canonical_graph_json(
        node.model_dump(mode="json", by_alias=True),
        label="GraphNode",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _projection_bytes(projection: GraphProjection) -> bytes:
    return canonical_graph_json(
        projection.model_dump(mode="json", by_alias=True),
        label="GraphProjection",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _snapshot_bytes(snapshot: GraphSnapshot) -> bytes:
    return canonical_graph_json(
        snapshot.model_dump(mode="json", by_alias=True),
        label="GraphSnapshot",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _action_permit_bytes(permit: ActionPermit) -> bytes:
    return canonical_graph_json(
        permit.model_dump(mode="json", by_alias=True),
        label="ActionPermit",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _action_approval_bytes(approval: ActionApprovalEnvelope) -> bytes:
    return canonical_graph_json(
        approval.model_dump(mode="json", by_alias=True),
        label="ActionApprovalEnvelope",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _approval_consumption_bytes(receipt: ActionApprovalConsumptionReceipt) -> bytes:
    return canonical_graph_json(
        receipt.model_dump(mode="json", by_alias=True),
        label="ActionApprovalConsumptionReceipt",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _cleanup_reservation_bytes(reservation: ActionCleanupReservation) -> bytes:
    return canonical_graph_json(
        reservation.model_dump(mode="json", by_alias=True),
        label="ActionCleanupReservation",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _cleanup_permit_bytes(permit: CleanupPermit) -> bytes:
    return canonical_graph_json(
        permit.model_dump(mode="json", by_alias=True),
        label="CleanupPermit",
        max_bytes=_MAX_GRAPH_BYTES,
    )


def _required_bytes(row: sqlite3.Row, field: str) -> bytes:
    value = row[field]
    if not isinstance(value, bytes):
        raise SQLiteGraphStoreError(f"SQLite Graph Store {field} is not canonical bytes")
    return value


def _decode_json(raw: bytes, *, label: str) -> object:
    if len(raw) > _MAX_GRAPH_BYTES:
        raise SQLiteGraphStoreError(f"SQLite Graph Store {label} exceeds byte limit")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SQLiteGraphStoreError(f"SQLite Graph Store {label} is not canonical JSON") from exc


def _canonical_event(event: GraphAdmissionEvent) -> GraphAdmissionEvent:
    try:
        return GraphAdmissionEvent.model_validate(event.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise GraphEventLogError("Graph admission event is not canonical") from exc


def _event_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> GraphAdmissionEvent:
    raw = _required_bytes(row, "event_json")
    try:
        event = GraphAdmissionEvent.model_validate(_decode_json(raw, label="GraphAdmissionEvent"))
    except ValidationError as exc:
        raise GraphEventLogError("stored Graph admission event is invalid") from exc
    if raw != _event_bytes(event):
        raise GraphEventLogError("stored Graph admission event is not canonical bytes")
    if (
        event.campaign_id != campaign_id
        or event.sequence != row["sequence"]
        or event.event_id != row["event_id"]
        or event.event_digest != row["event_digest"]
        or event.previous_event_digest != row["previous_event_digest"]
        or event.proposal_id != row["proposal_id"]
        or event.proposal_digest != row["proposal_digest"]
        or event.decision.value != row["decision"]
    ):
        raise GraphEventLogError("stored Graph admission event index differs from payload")
    return event


def _node_from_row(row: sqlite3.Row, *, campaign_id: str) -> GraphNode:
    raw = _required_bytes(row, "node_json")
    try:
        node = parse_graph_node(_decode_json(raw, label="GraphNode"))
    except ValidationError as exc:
        raise GraphEventLogError("stored Graph node is invalid") from exc
    if raw != _node_bytes(node):
        raise GraphEventLogError("stored Graph node is not canonical bytes")
    if (
        node.campaign_id != campaign_id
        or node.node_id != row["node_id"]
        or GraphNodeKind(node.kind).value != row["node_kind"]
    ):
        raise GraphEventLogError("stored Graph node index differs from payload")
    return node


def _projection_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> GraphProjection:
    raw = _required_bytes(row, "projection_json")
    try:
        projection = GraphProjection.model_validate(_decode_json(raw, label="GraphProjection"))
    except ValidationError as exc:
        raise GraphProjectionError("stored Graph projection is invalid") from exc
    if raw != _projection_bytes(projection):
        raise GraphProjectionError("stored Graph projection is not canonical bytes")
    if (
        projection.campaign_id != campaign_id
        or projection.revision != row["revision"]
        or projection.event_log_head_digest != row["event_log_head_digest"]
        or projection.projection_id != row["projection_id"]
        or projection.projection_digest != row["projection_digest"]
    ):
        raise GraphProjectionError("stored Graph projection index differs from payload")
    return projection


def _canonical_snapshot(snapshot: GraphSnapshot) -> GraphSnapshot:
    try:
        return GraphSnapshot.model_validate(snapshot.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise GraphSnapshotError("Graph Snapshot is not canonical") from exc


def _snapshot_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> GraphSnapshot:
    raw = _required_bytes(row, "snapshot_json")
    try:
        snapshot = GraphSnapshot.model_validate(_decode_json(raw, label="GraphSnapshot"))
    except ValidationError as exc:
        raise GraphSnapshotError("stored Graph Snapshot is invalid") from exc
    if raw != _snapshot_bytes(snapshot):
        raise GraphSnapshotError("stored Graph Snapshot is not canonical bytes")
    if (
        snapshot.campaign_id != campaign_id
        or snapshot.snapshot_id != row["snapshot_id"]
        or snapshot.snapshot_digest != row["snapshot_digest"]
        or snapshot.previous_snapshot_digest != row["previous_snapshot_digest"]
        or snapshot.revision != row["revision"]
        or snapshot.projection_digest != row["projection_digest"]
    ):
        raise GraphSnapshotError("stored Graph Snapshot index differs from payload")
    return snapshot


def _canonical_mission_envelope(envelope: MissionEnvelope) -> MissionEnvelope:
    try:
        return MissionEnvelope.model_validate(envelope.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise ActionPermitError("MissionEnvelope is not canonical") from exc


def _canonical_action_proposal(proposal: ActionProposal) -> ActionProposal:
    try:
        return ActionProposal.model_validate(proposal.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise ActionPermitError("ActionProposal is not canonical") from exc


def _canonical_graph_decision(decision: GraphDecision) -> GraphDecision:
    try:
        return GraphDecision.model_validate(decision.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise ActionPermitError("GraphDecision is not canonical") from exc


def _canonical_registered_capability(
    capability: RegisteredActionCapability,
) -> RegisteredActionCapability:
    try:
        return RegisteredActionCapability.model_validate(
            capability.model_dump(mode="json", by_alias=True)
        )
    except ValidationError as exc:
        raise ActionPermitError("Registered Action Capability is not canonical") from exc


def _canonical_action_approval(
    approval: ActionApprovalEnvelope,
) -> ActionApprovalEnvelope:
    try:
        return ActionApprovalEnvelope.model_validate(
            approval.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise ActionApprovalError("Action approval Envelope is not canonical") from exc


def _canonical_cleanup_reservation_request(
    request: ActionCleanupReservationRequest,
) -> ActionCleanupReservationRequest:
    try:
        return ActionCleanupReservationRequest.model_validate(
            request.model_dump(mode="json", by_alias=True)
        )
    except ValidationError as exc:
        raise CleanupPermitError("cleanup reservation request is not canonical") from exc


def _canonical_cleanup_request(request: CleanupRequest) -> CleanupRequest:
    try:
        return CleanupRequest.model_validate(request.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise CleanupPermitError("CleanupRequest is not canonical") from exc


def _action_permit_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> ActionPermit:
    raw = _required_bytes(row, "permit_json")
    try:
        permit = ActionPermit.model_validate(_decode_json(raw, label="ActionPermit"))
    except ValidationError as exc:
        raise ActionPermitError("stored ActionPermit is invalid") from exc
    if raw != _action_permit_bytes(permit):
        raise ActionPermitError("stored ActionPermit is not canonical bytes")
    if (
        permit.campaign_id != campaign_id
        or permit.permit_id != row["permit_id"]
        or permit.permit_digest != row["permit_digest"]
        or permit.dispatch_id != row["dispatch_id"]
        or permit.envelope_id != row["envelope_id"]
        or permit.envelope_digest != row["envelope_digest"]
        or permit.proposal_id != row["proposal_id"]
        or permit.proposal_digest != row["proposal_digest"]
        or permit.decision_id != row["decision_id"]
        or permit.decision_digest != row["decision_digest"]
        or permit.snapshot.snapshot_id != row["snapshot_id"]
        or permit.snapshot.snapshot_digest != row["snapshot_digest"]
        or permit.snapshot.revision != row["revision"]
        or permit.snapshot.event_log_head_digest != row["event_log_head_digest"]
        or permit.snapshot.projection_digest != row["projection_digest"]
        or permit.request_id != row["request_id"]
        or permit.request_digest != row["request_digest"]
        or permit.reservation.request_units != row["request_units"]
        or permit.reservation.cost_microusd != row["cost_microusd"]
        or permit.issued_at.isoformat() != row["issued_at"]
        or permit.consumed_at.isoformat() != row["consumed_at"]
        or permit.expires_at.isoformat() != row["expires_at"]
    ):
        raise ActionPermitError("stored ActionPermit index differs from payload")
    return permit


def _action_approval_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> ActionApprovalEnvelope:
    raw = _required_bytes(row, "approval_json")
    try:
        approval = ActionApprovalEnvelope.model_validate(
            _decode_json(raw, label="ActionApprovalEnvelope")
        )
    except ValidationError as exc:
        raise ActionApprovalError("stored Action approval is invalid") from exc
    if raw != _action_approval_bytes(approval):
        raise ActionApprovalError("stored Action approval is not canonical bytes")
    proposal = approval.proposal
    if (
        approval.campaign_id != campaign_id
        or approval.approval_id != row["approval_id"]
        or approval.approval_digest != row["approval_digest"]
        or approval.campaign_id != row["campaign_id"]
        or approval.run_id != row["run_id"]
        or approval.mission_envelope.envelope_id != row["envelope_id"]
        or approval.mission_envelope.envelope_digest != row["envelope_digest"]
        or approval.issuer.authority_id != row["issuer_authority_id"]
        or approval.issuer.authority_digest != row["issuer_authority_digest"]
        or approval.release.capability_id != row["capability_id"]
        or approval.release.capability_version != row["capability_version"]
        or approval.release.capability_digest != row["capability_digest"]
        or approval.release.release_id != row["release_id"]
        or approval.release.release_digest != row["release_digest"]
        or proposal.proposal_id != row["proposal_id"]
        or proposal.proposal_digest != row["proposal_digest"]
        or proposal.target_digest != row["target_digest"]
        or proposal.request_id != row["request_id"]
        or proposal.request_digest != row["request_digest"]
        or proposal.normalized_parameters_digest != row["normalized_parameters_digest"]
        or proposal.risk_tier.name != row["risk_tier"]
        or proposal.reservation.request_units != row["request_units"]
        or proposal.reservation.cost_microusd != row["cost_microusd"]
        or approval.approved_at.isoformat() != row["approved_at"]
        or approval.not_before.isoformat() != row["not_before"]
        or approval.expires_at.isoformat() != row["expires_at"]
    ):
        raise ActionApprovalError("stored Action approval index differs from payload")
    return approval


def _approval_consumption_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> ActionApprovalConsumptionReceipt:
    raw = _required_bytes(row, "receipt_json")
    try:
        receipt = ActionApprovalConsumptionReceipt.model_validate(
            _decode_json(raw, label="ActionApprovalConsumptionReceipt")
        )
    except ValidationError as exc:
        raise ActionApprovalError("stored Action approval receipt is invalid") from exc
    if raw != _approval_consumption_bytes(receipt):
        raise ActionApprovalError("stored Action approval receipt is not canonical bytes")
    approval = receipt.approval
    permit = receipt.action_permit
    if (
        approval.campaign_id != campaign_id
        or receipt.receipt_id != row["receipt_id"]
        or receipt.receipt_digest != row["receipt_digest"]
        or approval.approval_id != row["approval_id"]
        or approval.approval_digest != row["approval_digest"]
        or permit.permit_id != row["permit_id"]
        or permit.permit_digest != row["permit_digest"]
        or receipt.dispatch_id != row["dispatch_id"]
        or receipt.proposal_id != row["proposal_id"]
        or receipt.proposal_digest != row["proposal_digest"]
        or receipt.request_id != row["request_id"]
        or receipt.request_digest != row["request_digest"]
        or receipt.normalized_parameters_digest != row["normalized_parameters_digest"]
        or permit.consumed_at.isoformat() != row["consumed_at"]
    ):
        raise ActionApprovalError("stored Action approval receipt index differs from payload")
    return receipt


def _cleanup_reservation_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> ActionCleanupReservation:
    raw = _required_bytes(row, "reservation_json")
    try:
        reservation = ActionCleanupReservation.model_validate(
            _decode_json(raw, label="ActionCleanupReservation")
        )
    except ValidationError as exc:
        raise CleanupPermitError("stored cleanup reservation is invalid") from exc
    if raw != _cleanup_reservation_bytes(reservation):
        raise CleanupPermitError("stored cleanup reservation is not canonical bytes")
    if (
        reservation.campaign_id != campaign_id
        or reservation.cleanup_reservation_id != row["cleanup_reservation_id"]
        or reservation.cleanup_reservation_digest != row["cleanup_reservation_digest"]
        or reservation.reservation_request_id != row["reservation_request_id"]
        or reservation.reservation_request_digest != row["reservation_request_digest"]
        or reservation.source_action_permit_id != row["source_action_permit_id"]
        or reservation.source_action_permit_digest != row["source_action_permit_digest"]
        or reservation.source_action_dispatch_id != row["source_action_dispatch_id"]
        or reservation.envelope_id != row["envelope_id"]
        or reservation.envelope_digest != row["envelope_digest"]
        or reservation.cleanup_capability.capability_digest
        != row["cleanup_capability_digest"]
        or reservation.target_digest != row["target_digest"]
        or reservation.cleanup_handler_digest != row["cleanup_handler_digest"]
        or reservation.cleanup_executor_digest != row["cleanup_executor_digest"]
        or reservation.reservation.tool_calls != row["tool_calls"]
        or reservation.reservation.request_units != row["request_units"]
        or reservation.reservation.cost_microusd != row["cost_microusd"]
        or reservation.reserved_at.isoformat() != row["reserved_at"]
        or reservation.claim_expires_at.isoformat() != row["claim_expires_at"]
    ):
        raise CleanupPermitError("stored cleanup reservation index differs from payload")
    return reservation


def _cleanup_permit_from_row(
    row: sqlite3.Row,
    *,
    campaign_id: str,
) -> CleanupPermit:
    raw = _required_bytes(row, "permit_json")
    try:
        permit = CleanupPermit.model_validate(_decode_json(raw, label="CleanupPermit"))
    except ValidationError as exc:
        raise CleanupPermitError("stored CleanupPermit is invalid") from exc
    if raw != _cleanup_permit_bytes(permit):
        raise CleanupPermitError("stored CleanupPermit is not canonical bytes")
    if (
        permit.campaign_id != campaign_id
        or permit.cleanup_permit_id != row["cleanup_permit_id"]
        or permit.cleanup_permit_digest != row["cleanup_permit_digest"]
        or permit.cleanup_dispatch_id != row["cleanup_dispatch_id"]
        or permit.cleanup_reservation_id != row["cleanup_reservation_id"]
        or permit.cleanup_reservation_digest != row["cleanup_reservation_digest"]
        or permit.source_action_permit_id != row["source_action_permit_id"]
        or permit.source_action_permit_digest != row["source_action_permit_digest"]
        or permit.envelope_id != row["envelope_id"]
        or permit.envelope_digest != row["envelope_digest"]
        or permit.cleanup_request_id != row["cleanup_request_id"]
        or permit.cleanup_request_digest != row["cleanup_request_digest"]
        or permit.decision_id != row["decision_id"]
        or permit.decision_digest != row["decision_digest"]
        or permit.snapshot.snapshot_id != row["snapshot_id"]
        or permit.snapshot.snapshot_digest != row["snapshot_digest"]
        or permit.snapshot.revision != row["revision"]
        or permit.snapshot.event_log_head_digest != row["event_log_head_digest"]
        or permit.snapshot.projection_digest != row["projection_digest"]
        or permit.request_id != row["request_id"]
        or permit.request_digest != row["request_digest"]
        or permit.capability.capability_digest != row["cleanup_capability_digest"]
        or permit.target_digest != row["target_digest"]
        or permit.cleanup_handler_digest != row["cleanup_handler_digest"]
        or permit.cleanup_executor_digest != row["cleanup_executor_digest"]
        or permit.cleanup_plan_digest != row["cleanup_plan_digest"]
        or permit.issued_at.isoformat() != row["issued_at"]
        or permit.consumed_at.isoformat() != row["consumed_at"]
        or permit.expires_at.isoformat() != row["expires_at"]
    ):
        raise CleanupPermitError("stored CleanupPermit index differs from payload")
    return permit


def _require_event_chain(
    events: tuple[GraphAdmissionEvent, ...],
    *,
    campaign_id: str,
) -> None:
    previous: str | None = None
    for sequence, event in enumerate(events, start=1):
        if (
            event.campaign_id != campaign_id
            or event.sequence != sequence
            or event.previous_event_digest != previous
        ):
            raise GraphEventLogError("stored Graph Event Log chain is not contiguous")
        previous = event.event_digest
