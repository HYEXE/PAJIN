"""Passive domain verification; no key enrollment, migration, refund or execution."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import inspect, select, text
from sqlalchemy.engine import make_url

from pajin.control_plane.database import (
    ArtifactRecord,
    CheckpointKeyIdentityRecord,
    CheckpointRecord,
    ControlPlaneRepository,
    JobRecord,
    ReplayExecutionContextRecord,
    ReplayItemRecord,
    RunRecord,
)
from pajin.control_plane.security import CheckpointSigner
from pajin.domain.models import Budgets, CampaignManifest
from pajin.graph.sqlite_store import SQLiteGraphSnapshotStore, load_verified_current_graph_snapshot
from pajin.operations.hybrid_docker import Postgres
from pajin.operations.hybrid_files import collect
from pajin.operations.hybrid_models import MAX_BYTES, Deployment, canonical, digest
from pajin.runtime.budget_persistence import _read_row, _verified_history
from pajin.runtime.budget_state import BUDGET_TABLE, BudgetScope
from pajin.runtime.host_checkpoint_stores import _integrity, readonly_database
from pajin.runtime.recovery_bindings import verify_original_run_data
from pajin.runtime.store import verify_run_integrity
from pajin.supervision.invocation_journal import _entry_from_row, _validate_schema
from pajin.supervision.run_binding import require_run_binding


def postgres_identity(repository: ControlPlaneRepository) -> str:
    with repository.engine.connect() as connection:
        return digest(
            list(
                connection.execute(
                    text(
                        "SELECT system_identifier::text, current_database(), "
                        "(SELECT oid::text FROM pg_database WHERE datname=current_database()) "
                        "FROM pg_control_system()",
                    )
                ).one()
            )
        )


def _rows(repository: ControlPlaneRepository, signer: CheckpointSigner) -> dict[str, object]:
    repository.schema_version()
    with repository.read_transaction() as session:
        session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        commitments = signer.key_commitments()
        for key in session.scalars(select(CheckpointKeyIdentityRecord)):
            if key.key_id in commitments and key.key_commitment != commitments[key.key_id]:
                raise ValueError("original checkpoint verifier identity differs")
        for checkpoint in session.scalars(select(CheckpointRecord)):
            signer.verify(
                checkpoint_id=checkpoint.checkpoint_id,
                run_id=checkpoint.run_id,
                sequence=checkpoint.sequence,
                schema_version=checkpoint.schema_version,
                payload=checkpoint.payload,
                payload_sha256=checkpoint.payload_sha256,
                signature=checkpoint.signature,
                key_id=checkpoint.key_id,
            )
        tables: dict[str, object] = {}
        size = 0
        for name in sorted(inspect(session.connection()).get_table_names()):
            if not name.startswith("cp_") or not name.replace("_", "").isalnum():
                raise ValueError("database has an undeclared table")
            rows = []
            for row in session.execute(text(f'SELECT * FROM "{name}"')).mappings():
                value = json.dumps(dict(row), sort_keys=True, default=str)
                size += len(value.encode())
                if size > MAX_BYTES:
                    raise ValueError("logical database exceeds recovery size limit")
                rows.append(value)
            tables[name] = sorted(rows)
    return tables


def _journal(
    repository: ControlPlaneRepository,
    state: Path,
    plan: Deployment,
) -> tuple[list[dict[str, object]], set[str]]:
    reports: list[dict[str, object]] = []
    covered: set[str] = set()
    for member in plan.journals:
        binding = member.binding
        with repository.read_transaction() as session:
            run = session.get(RunRecord, binding.control_plane_run_id)
            kinds = tuple(
                session.scalars(
                    select(JobRecord.kind)
                    .where(
                        JobRecord.run_id == binding.control_plane_run_id,
                    )
                    .distinct()
                )
            )
            contexts = tuple(
                session.scalars(
                    select(ReplayExecutionContextRecord.canonical_context).where(
                        ReplayExecutionContextRecord.replay_run_id == binding.control_plane_run_id,
                    )
                )
            )
            verify_original_run_data(
                binding,
                original_run=None
                if run is None
                else (
                    run.campaign_name,
                    json.dumps(run.input),
                ),
                job_kinds=kinds,
                replay_contexts=contexts,
            )
            if run is None or "manifest" not in run.input or binding.budget_mode != "campaign-only":
                raise ValueError("operator recovery requires manifest-bound campaign-only journals")
            campaign = CampaignManifest.model_validate(run.input["manifest"])
        with readonly_database(state / member.path) as connection:
            _integrity(connection)
            _validate_schema(connection)
            require_run_binding(connection, binding)
            expected = BudgetScope(
                campaign_digest=binding.campaign_digest,
                role="campaign",
                policy_digest=None,
                limits=campaign.spec.budgets,
            )
            for row in connection.execute(f"SELECT * FROM {BUDGET_TABLE}"):
                if _read_row(row).scope != expected:
                    raise ValueError("budget scope differs from the original Campaign")
            saved = _verified_history(connection, expected)
            if saved is None:
                raise ValueError("journal lacks conservative budget history")
            unknown = 0
            for row in connection.execute("SELECT * FROM supervisor_invocation_intents"):
                entry = _entry_from_row(connection, row)
                if entry.intent.campaign_digest != binding.campaign_digest:
                    raise ValueError("journal invocation belongs to another Campaign")
                unknown += entry.state == "dispatch-started-outcome-unknown"
            reports.append(
                {
                    "run_id": binding.control_plane_run_id,
                    "scope": expected.model_dump(mode="json"),
                    "origin_at": saved.origin_at.isoformat(),
                    "recorded_at": saved.recorded_at.isoformat(),
                    "usage": saved.usage.model_dump(mode="json"),
                    "uncertain_calls": unknown,
                }
            )
            covered.add(binding.control_plane_run_id)
    return reports, covered


def verify_state(
    state: Path,
    plan: Deployment,
    *,
    database_url: str,
    signer: CheckpointSigner,
) -> dict[str, object]:
    url = make_url(database_url)
    if url.get_backend_name() != "postgresql" or url.query.get("sslmode") != "verify-full":
        raise ValueError("recovery requires PostgreSQL with verified TLS")
    if signer.key_commitments() != plan.checkpoint_key_commitments:
        raise ValueError("runtime verifier differs from the independently pinned key inventory")
    files = collect(state)
    allowed = {m.path for m in plan.graphs} | {m.path for m in plan.journals}
    run_prefixes = tuple(m.path + "/" for m in plan.runs)
    if any(obj.path not in allowed and not obj.path.startswith(run_prefixes) for obj in files):
        raise ValueError("local state contains undeclared files or SQLite sidecars")
    if not allowed <= {obj.path for obj in files}:
        raise ValueError("local state is missing a required database")
    repository = ControlPlaneRepository(database_url)
    try:
        if postgres_identity(repository) != Postgres(plan).identity():
            raise ValueError("TLS database differs from the pinned administrative database")
        tables = _rows(repository, signer)
        budgets, covered = _journal(repository, state, plan)
        with repository.read_transaction() as session:
            if (
                session.scalar(select(ArtifactRecord.artifact_id).limit(1)) is not None
                or session.scalar(select(ReplayItemRecord.item_id).limit(1)) is not None
            ):
                raise ValueError(
                    "managed artifact repositories and Replay require another contract"
                )
            attempted = set(
                session.scalars(
                    select(JobRecord.run_id).where(
                        JobRecord.attempts > 0,
                    )
                )
            )
            if not attempted <= covered:
                raise ValueError("attempted Runs are missing their original budget journals")
    finally:
        repository.close()
    graphs = []
    for member in plan.graphs:
        history = SQLiteGraphSnapshotStore(
            state / member.path, campaign_id=member.campaign_id
        ).snapshots()
        if not history:
            raise ValueError("required Graph has no verified snapshot history")
        snapshot = load_verified_current_graph_snapshot(
            state / member.path, campaign_id=member.campaign_id, snapshot_id=history[-1].snapshot_id
        )
        if snapshot is None:
            raise ValueError("required Graph has no verified current snapshot")
        graphs.append(
            {
                "path": member.path,
                "snapshot_id": snapshot.snapshot_id,
                "digest": snapshot.snapshot_digest,
            }
        )
    runs = []
    for run_member in plan.runs:
        verified = verify_run_integrity(state / run_member.path)
        if verified.run_id != run_member.run_id:
            raise ValueError("sealed Run identity differs from its inventory")
        runs.append(
            {
                "path": run_member.path,
                "run_id": verified.run_id,
                "root_digest": verified.root_digest,
            }
        )
    if files != collect(state):
        raise ValueError("state changed during semantic verification")
    return {
        "postgres_rows_sha256": digest(tables),
        "files_sha256": digest([item.model_dump(mode="json") for item in files]),
        "graphs": graphs,
        "runs": runs,
        "budgets": budgets,
        "execution_authorized": False,
        "external_rollback": "unknown",
    }


def require_resume_budget(summary: dict[str, object], run_id: str, *, now: datetime) -> None:
    # Recompute duration at resume time, never from a stale successful restore report.
    budgets = json.loads(canonical(summary["budgets"]))
    found = [item for item in budgets if item["run_id"] == run_id]
    if len(found) != 1 or found[0]["uncertain_calls"]:
        raise ValueError("resume has missing accounting or an uncertain invocation")
    item = found[0]
    origin = datetime.fromisoformat(item["origin_at"])
    recorded = datetime.fromisoformat(item["recorded_at"])
    if now.tzinfo is None or now < recorded or now < origin:
        raise ValueError("resume clock is not current UTC")
    elapsed = max(item["usage"]["elapsed_seconds"], (now.astimezone(UTC) - origin).total_seconds())
    limits = Budgets.model_validate(item["scope"]["limits"])
    if elapsed >= limits.duration_seconds:
        raise ValueError("restored duration budget has expired")
