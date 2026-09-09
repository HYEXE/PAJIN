"""Read-only domain checks for a closed local SQLite recovery set."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path

from sqlalchemy import select

from pajin.control_plane.database import (
    CheckpointKeyIdentityRecord,
    CheckpointRecord,
    ControlPlaneRepository,
)
from pajin.control_plane.security import CheckpointSigner
from pajin.runtime.budget_persistence import _read_row, _verified_history
from pajin.runtime.budget_state import BUDGET_TABLE
from pajin.runtime.host_checkpoint_models import (
    MAX_CHECKPOINT_BYTES,
    HostCheckpointError,
    HostCheckpointPlan,
)
from pajin.runtime.safe_files import read_bounded_regular_bytes
from pajin.supervision.invocation_journal import _entry_from_row, _validate_schema
from pajin.supervision.run_binding import SupervisorRunBinding, require_run_binding


@contextmanager
def readonly_database(path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=1)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA query_only = ON")
        size = connection.execute("PRAGMA page_count").fetchone()[0] * connection.execute(
            "PRAGMA page_size",
        ).fetchone()[0]
        if size > MAX_CHECKPOINT_BYTES:
            raise HostCheckpointError("checkpoint database exceeds its byte limit")
        yield connection
    finally:
        connection.close()


def _integrity(connection: sqlite3.Connection) -> None:
    if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [("ok",)]:
        raise HostCheckpointError("checkpoint SQLite integrity failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise HostCheckpointError("checkpoint SQLite foreign-key integrity failed")


def verify_control_plane(path: Path, signer: CheckpointSigner) -> tuple[set[str], set[str]]:
    """Never initialize, migrate, bind a key, or reconcile a lease during backup/restore."""
    repository = ControlPlaneRepository(f"sqlite+pysqlite:///{path.as_uri()}?mode=ro&uri=true")
    try:
        repository.schema_version()
        with repository.read_transaction() as session:
            commitments = signer.key_commitments()
            for stored in session.scalars(select(CheckpointKeyIdentityRecord)):
                if stored.key_id in commitments and (
                    stored.key_commitment != commitments[stored.key_id]
                ):
                    raise HostCheckpointError("checkpoint verification key identity differs")
            for checkpoint in session.scalars(select(CheckpointRecord)):
                signer.verify(
                    checkpoint_id=checkpoint.checkpoint_id, run_id=checkpoint.run_id,
                    sequence=checkpoint.sequence, schema_version=checkpoint.schema_version,
                    payload=checkpoint.payload, payload_sha256=checkpoint.payload_sha256,
                    signature=checkpoint.signature, key_id=checkpoint.key_id,
                )
    finally:
        repository.close()
    with readonly_database(path) as connection:
        _integrity(connection)
        # A dead process or cancelled Run is not proof of an absent side effect.
        for query in (
            "SELECT 1 FROM cp_runs WHERE state = 'running' LIMIT 1",
            "SELECT 1 FROM cp_jobs WHERE state = 'leased' "
            "OR (attempts > 0 AND state != 'succeeded') LIMIT 1",
            "SELECT 1 FROM cp_replay_tickets WHERE state IN ('claimed', 'abandoned') LIMIT 1",
            "SELECT 1 FROM cp_replay_items WHERE state IN ('running', 'retry-pending') LIMIT 1",
        ):
            if connection.execute(query).fetchone() is not None:
                raise HostCheckpointError("Control Plane has active or uncertain execution")
        return (
            {str(row[0]) for row in connection.execute("SELECT run_id FROM cp_runs")},
            {str(row[0]) for row in connection.execute(
                "SELECT DISTINCT run_id FROM cp_jobs WHERE attempts > 0",
            )},
        )


def verify_supervisor(path: Path, binding: SupervisorRunBinding) -> None:
    with readonly_database(path) as connection:
        _integrity(connection)
        _validate_schema(connection)
        require_run_binding(connection, binding)
        scopes = {}
        for row in connection.execute(f"SELECT * FROM {BUDGET_TABLE} ORDER BY scope_id, revision"):
            checkpoint = _read_row(row)
            if checkpoint.scope.campaign_digest != binding.campaign_digest:
                raise HostCheckpointError("journal budget belongs to another Campaign")
            scopes[checkpoint.scope.role] = checkpoint.scope
        expected = {"campaign"} if binding.budget_mode == "campaign-only" else {
            "campaign", "supervisor",
        }
        if set(scopes) != expected:
            raise HostCheckpointError("journal has incomplete budget history")
        for scope in scopes.values():
            _verified_history(connection, scope)
        for row in connection.execute("SELECT * FROM supervisor_invocation_intents"):
            entry = _entry_from_row(connection, row)
            if entry.intent.campaign_digest != binding.campaign_digest:
                raise HostCheckpointError("Supervisor intent belongs to another Campaign")
            if entry.state == "dispatch-started-outcome-unknown":
                raise HostCheckpointError("Supervisor has an uncertain dispatch")


def verify_graph_quiescence(path: Path) -> None:
    with readonly_database(path) as connection:
        _integrity(connection)
        # This narrow recovery set has no independent physical-cleanup reconciler.
        # Preserve reservations in place; never treat a permit/receipt as cleanup.
        if connection.execute("SELECT 1 FROM graph_action_cleanup_reservations LIMIT 1").fetchone():
            raise HostCheckpointError("reversible Graph writes require separate reconciliation")


def verify_recovery_stores(
    state: Path, plan: HostCheckpointPlan, *, checkpoint_signer: CheckpointSigner,
) -> None:
    from pajin.runtime.registered_checkpoint import verify_registered_checkpoint_members

    verify_registered_checkpoint_members(state, plan)
    cp = next(member for member in plan.members if member.kind == "control-plane-sqlite")
    run_ids, attempted_runs = verify_control_plane(state / cp.path, checkpoint_signer)
    budgeted_runs = {
        member.run_binding.control_plane_run_id for member in plan.members
        if member.run_binding is not None
    }
    if not attempted_runs <= budgeted_runs:
        raise HostCheckpointError(
            "previously attempted Runs require their complete budget journals",
        )
    for member in plan.members:
        if member.run_binding is not None:
            if member.run_binding.control_plane_run_id not in run_ids:
                raise HostCheckpointError("journal Run is missing from the Control Plane")
            verify_supervisor(state / member.path, member.run_binding)
            if plan.enrollment is not None:
                from pajin.runtime.recovery_bindings import verify_original_run_binding

                with readonly_database(state / cp.path) as connection:
                    verify_original_run_binding(connection, member.run_binding)
        elif member.kind == "graph-sqlite":
            verify_graph_quiescence(state / member.path)
        elif member.kind == "artifact":
            content = read_bounded_regular_bytes(
                state / member.path, max_bytes=MAX_CHECKPOINT_BYTES,
                label="checkpoint artifact", require_single_link=True,
            )
            if sha256(content).hexdigest() != member.artifact_sha256 or content.startswith(
                b"SQLite format 3\0",
            ):
                raise HostCheckpointError("artifact differs from its expected content")
