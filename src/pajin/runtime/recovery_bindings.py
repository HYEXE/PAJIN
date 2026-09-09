"""Compare enrolled producer inputs with original Control Plane and sealed Run state."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pajin.domain.models import CampaignManifest
    from pajin.supervision.run_binding import SupervisorRunBinding


def require_registered_control_plane(database_url: str) -> None:
    from sqlalchemy.engine import make_url

    from pajin.runtime.host_gate import recovery_activity
    from pajin.runtime.host_recovery import (
        RecoveryEnrollmentError,
        _member_path,
        inspect_recovery_inventory,
    )

    active = recovery_activity()
    if active is None:
        return
    lease, _ = active
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.query:
        raise RecoveryEnrollmentError("recovery producer CP must be enrolled local SQLite")
    path = _member_path(lease.root, Path(url.database).absolute())
    if not any(
        item.path == path and item.kind == "control-plane-sqlite"
        for item in inspect_recovery_inventory(lease).registrations
    ):
        raise RecoveryEnrollmentError("recovery producer Control Plane is not enrolled")


def verify_original_run_binding(
    connection: sqlite3.Connection,
    binding: SupervisorRunBinding,
    *,
    campaign: CampaignManifest | None = None,
) -> None:
    from pajin.control_plane.executors import (
        CampaignJobInput,
        CapabilityGraphBatchCampaignJobInput,
        CapabilityGraphCampaignJobInput,
        GeneralAttackCampaignJobInput,
        ToolLoopJobInput,
    )
    from pajin.control_plane.models import (
        ReplayExecutionContext,
        canonical_replay_execution_context_bytes,
        replay_execution_component_digest,
    )
    from pajin.runtime.safe_files import parse_strict_json_bytes

    run = connection.execute(
        "SELECT campaign_name, input FROM cp_runs WHERE run_id = ?",
        (binding.control_plane_run_id,),
    ).fetchone()
    kinds = connection.execute(
        "SELECT DISTINCT kind FROM cp_jobs WHERE run_id = ?",
        (binding.control_plane_run_id,),
    ).fetchall()
    if run is None or len(kinds) != 1:
        raise ValueError("recovery binding requires one original Control Plane Run kind")
    kind = str(kinds[0][0])
    original: object
    expected_campaign: CampaignManifest | None = None
    if kind == "internal-replay":
        rows = connection.execute(
            "SELECT canonical_context FROM cp_replay_execution_contexts WHERE replay_run_id = ?",
            (binding.control_plane_run_id,),
        ).fetchall()
        if len(rows) != 1:
            raise ValueError("recovery binding requires the exact Replay execution context")
        content = bytes(rows[0][0])
        context = ReplayExecutionContext.model_validate(
            parse_strict_json_bytes(
                content,
                label="recovery Replay context",
                max_bytes=4 * 1024 * 1024,
            )
        )
        if (
            context.replay_run_id != binding.control_plane_run_id
            or content != canonical_replay_execution_context_bytes(context)
        ):
            raise ValueError("recovery Replay context differs from its original Run")
        original, expected_campaign = context, context.campaign
    else:
        raw = parse_strict_json_bytes(
            str(run[1]).encode(),
            label="recovery original Run input",
            max_bytes=4 * 1024 * 1024,
        )
        if not isinstance(raw, dict):
            raise ValueError("recovery Run input must be an object")
        profile = raw.get("profile", "deterministic-local")
        if kind == "tool-loop":
            tool_loop = ToolLoopJobInput.model_validate(raw)
            original, expected_campaign = tool_loop, tool_loop.manifest
        elif kind != "campaign":
            raise ValueError("recovery Run kind has no original input verifier")
        elif profile == "deterministic-local":
            local = CampaignJobInput.model_validate(raw)
            original, expected_campaign = local, local.manifest
        elif profile == "capability-graph-batch-v1":
            original = CapabilityGraphBatchCampaignJobInput.model_validate(raw)
        elif profile in {"general-attack-v1", "general-attack-approved-v1"}:
            original = GeneralAttackCampaignJobInput.model_validate(raw)
        else:
            original = CapabilityGraphCampaignJobInput.model_validate(raw)
    if replay_execution_component_digest({"kind": kind, "input": original}) != binding.input_digest:
        raise ValueError("recovery journal differs from the original Control Plane input")
    for checked in (expected_campaign, campaign):
        _verify_campaign_binding(binding, checked, campaign_name=str(run[0]))


def _verify_campaign_binding(
    binding: SupervisorRunBinding, campaign: CampaignManifest | None, *, campaign_name: str,
) -> None:
    if campaign is None:
        return
    if binding.budget_mode == "campaign-and-supervisor":
        from pajin.workflow.profile_compatibility import compile_legacy_campaign_profile

        digest = compile_legacy_campaign_profile(campaign).input_digest
    else:
        from pajin.control_plane.models import replay_execution_component_digest

        digest = replay_execution_component_digest(campaign)
    if campaign.metadata.name != campaign_name or digest != binding.campaign_digest:
        raise ValueError("recovery journal differs from the original Campaign")


def require_registered_producer(
    *,
    graph_store: object,
    sources: tuple[tuple[Path, str, str], ...],
    journal_path: Path | None = None,
    campaign: CampaignManifest | None = None,
) -> None:
    """A v3 producer must consume already enrolled SQLite and exact sealed source Runs."""
    from pajin.graph.sqlite_store import SQLiteGraphSnapshotStore
    from pajin.runtime.host_checkpoint_stores import readonly_database
    from pajin.runtime.host_gate import recovery_activity
    from pajin.runtime.host_recovery import (
        RecoveryEnrollmentError,
        _member_path,
        inspect_recovery_inventory,
    )
    from pajin.runtime.store import verify_run_integrity

    active = recovery_activity()
    if active is None:
        return
    lease, _ = active
    registered = {item.path: item for item in inspect_recovery_inventory(lease).registrations}
    if type(graph_store) is not SQLiteGraphSnapshotStore:
        raise RecoveryEnrollmentError("recovery producer requires its enrolled SQLite Graph")
    graph = registered.get(_member_path(lease.root, graph_store.path))
    if graph is None or graph.kind != "graph-sqlite":
        raise RecoveryEnrollmentError("recovery producer Graph is not enrolled")
    if journal_path is not None:
        journal = registered.get(_member_path(lease.root, journal_path))
        cp = [item for item in registered.values() if item.kind == "control-plane-sqlite"]
        if journal is None or journal.run_binding is None or len(cp) != 1:
            raise RecoveryEnrollmentError("recovery producer requires its enrolled Run and CP")
        with readonly_database(lease.root / "state" / cp[0].path) as connection:
            verify_original_run_binding(connection, journal.run_binding, campaign=campaign)
    for path, run_id, root_digest in sources:
        run = registered.get(_member_path(lease.root, path))
        if run is None or run.kind != "run-store" or run.run_id != run_id:
            raise RecoveryEnrollmentError("recovery producer source Run is not enrolled")
        verified = verify_run_integrity(path)
        if verified.run_id != run_id or verified.root_digest != root_digest:
            raise RecoveryEnrollmentError("recovery producer source differs from its exact seal")
