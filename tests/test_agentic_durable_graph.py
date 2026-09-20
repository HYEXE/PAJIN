from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

import pajin.agentic.durable_graph as durable_graph
import pajin.graph.sqlite_store as sqlite_store
from pajin.agentic.durable_graph import (
    AgenticGraphHeadError,
    CurrentGraphHeadResolver,
    VerifiedCurrentGraphHead,
)
from pajin.graph import (
    GraphProjectionCoordinator,
    GraphSnapshot,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    SQLiteGraphStore,
    graph_snapshot_ref,
)
from pajin.graph.sqlite_store import (
    load_verified_current_graph_snapshot_from_descriptor,
)

CAMPAIGN = "agentic-durable"
CREATOR = "pajin.agentic.durable-graph-tests"
CREATOR_DIGEST = "a" * 64
NOW = datetime(2026, 9, 18, tzinfo=UTC)


def _graph_authority(
    path: Path,
) -> tuple[SQLiteGraphStore, GraphSnapshotAuthority]:
    store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()
    authority = GraphSnapshotAuthority(
        creator_id=CREATOR,
        creator_digest=CREATOR_DIGEST,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW,
    )
    return store, authority


def _current_snapshot(path: Path) -> GraphSnapshot:
    _store, authority = _graph_authority(path)
    return authority.capture(GraphSnapshotReason.CHECKPOINT)


def test_resolver_issues_opaque_head_and_revalidates_before_planning(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph" / "canonical.sqlite3"
    snapshot = _current_snapshot(path)
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    resolver = CurrentGraphHeadResolver(path, campaign_id=CAMPAIGN)

    handle = resolver.resolve(graph_snapshot_ref(snapshot))
    resolved = resolver.snapshot_for_planning(handle)

    assert type(handle) is VerifiedCurrentGraphHead
    assert handle.reference == graph_snapshot_ref(snapshot)
    assert handle.campaign_id == CAMPAIGN
    assert handle.snapshot_id == snapshot.snapshot_id
    assert handle.snapshot_digest == snapshot.snapshot_digest
    assert resolved == snapshot
    assert resolved is not snapshot
    assert not hasattr(handle, "snapshot")
    assert not hasattr(handle, "model_dump")
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    with pytest.raises(TypeError, match="opaque"):
        VerifiedCurrentGraphHead()
    with pytest.raises(AttributeError, match="immutable"):
        handle._reference = graph_snapshot_ref(snapshot)
    with pytest.raises(AttributeError, match="deployment binding is immutable"):
        resolver._campaign_id = "other-campaign"
    resolver.close()
    resolver.close()
    with pytest.raises(AgenticGraphHeadError, match="resolver is closed"):
        resolver.snapshot_for_planning(handle)


def test_durable_seam_rejects_raw_snapshot_before_any_store_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "graph" / "canonical.sqlite3"
    snapshot = _current_snapshot(path)
    resolver = CurrentGraphHeadResolver(path, campaign_id=CAMPAIGN)
    calls = 0

    def unexpected_loader(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise AssertionError("raw Snapshot reached the durable loader")

    monkeypatch.setattr(
        durable_graph,
        "load_verified_current_graph_snapshot_from_descriptor",
        unexpected_loader,
    )

    with pytest.raises(TypeError, match="verified Graph head handle"):
        resolver.snapshot_for_planning(snapshot)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="GraphSnapshotRef"):
        resolver.resolve(snapshot)  # type: ignore[arg-type]
    foreign = graph_snapshot_ref(snapshot).model_copy(
        update={"campaign_id": "other-campaign"}
    )
    with pytest.raises(AgenticGraphHeadError, match="another deployment Campaign"):
        resolver.resolve(foreign)
    assert calls == 0


def test_forged_and_cross_resolver_handles_fail_before_store_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "graph" / "canonical.sqlite3"
    snapshot = _current_snapshot(path)
    first = CurrentGraphHeadResolver(path, campaign_id=CAMPAIGN)
    second = CurrentGraphHeadResolver(path, campaign_id=CAMPAIGN)
    handle = first.resolve(graph_snapshot_ref(snapshot))
    forged = object.__new__(VerifiedCurrentGraphHead)
    calls = 0

    def unexpected_loader(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise AssertionError("untrusted handle reached the durable loader")

    monkeypatch.setattr(
        durable_graph,
        "load_verified_current_graph_snapshot_from_descriptor",
        unexpected_loader,
    )

    with pytest.raises(AgenticGraphHeadError, match="another resolver"):
        second.snapshot_for_planning(handle)
    with pytest.raises(AgenticGraphHeadError, match="incomplete"):
        first.snapshot_for_planning(forged)
    assert calls == 0


def test_resolver_rejects_noncurrent_and_exact_reference_mismatch(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph" / "canonical.sqlite3"
    _store, authority = _graph_authority(path)
    first = authority.capture(GraphSnapshotReason.CHECKPOINT)
    resolver = CurrentGraphHeadResolver(path, campaign_id=CAMPAIGN)
    stale_handle = resolver.resolve(graph_snapshot_ref(first))
    second = authority.capture(GraphSnapshotReason.HANDOFF)

    with pytest.raises(AgenticGraphHeadError, match="verification failed"):
        resolver.resolve(graph_snapshot_ref(first))
    with pytest.raises(AgenticGraphHeadError, match="verification failed"):
        resolver.snapshot_for_planning(stale_handle)

    current_reference = graph_snapshot_ref(second)
    mismatches = (
        {"snapshot_id": "graph-snapshot_" + "b" * 64},
        {"snapshot_digest": "b" * 64},
        {"projection_digest": "c" * 64},
        {"revision": 1, "event_log_head_digest": "d" * 64},
    )
    for mismatch in mismatches:
        with pytest.raises(AgenticGraphHeadError):
            resolver.resolve(current_reference.model_copy(update=mismatch))

    handle = resolver.resolve(current_reference)
    assert resolver.snapshot_for_planning(handle) == second


def test_bound_resolver_rejects_physical_store_replacement(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph" / "canonical.sqlite3"
    snapshot = _current_snapshot(path)
    resolver = CurrentGraphHeadResolver(path, campaign_id=CAMPAIGN)
    handle = resolver.resolve(graph_snapshot_ref(snapshot))
    replacement = path.with_name("replacement.sqlite3")
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o600)

    os.replace(replacement, path)

    with pytest.raises(AgenticGraphHeadError, match="identity changed"):
        resolver.snapshot_for_planning(handle)


def test_pinned_descriptor_rejects_swap_restore_to_another_valid_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"
    first_path = first_directory / "canonical.sqlite3"
    second_path = second_directory / "canonical.sqlite3"
    first = _current_snapshot(first_path)
    _second_store, second_authority = _graph_authority(second_path)
    second_authority.capture(GraphSnapshotReason.CHECKPOINT)
    second = second_authority.capture(GraphSnapshotReason.HANDOFF)
    resolver = CurrentGraphHeadResolver(first_path, campaign_id=CAMPAIGN)
    original_loader = load_verified_current_graph_snapshot_from_descriptor
    holding_directory = tmp_path / "holding"

    def swap_restore_loader(
        descriptor: int,
        *,
        parent_descriptor: int,
        database_name: str,
        campaign_id: str,
        snapshot_id: str,
    ) -> GraphSnapshot | None:
        os.rename(first_directory, holding_directory)
        os.rename(second_directory, first_directory)
        try:
            return original_loader(
                descriptor,
                parent_descriptor=parent_descriptor,
                database_name=database_name,
                campaign_id=campaign_id,
                snapshot_id=snapshot_id,
            )
        finally:
            os.rename(first_directory, second_directory)
            os.rename(holding_directory, first_directory)

    monkeypatch.setattr(
        durable_graph,
        "load_verified_current_graph_snapshot_from_descriptor",
        swap_restore_loader,
    )

    with pytest.raises(AgenticGraphHeadError, match="current durable head"):
        resolver.resolve(graph_snapshot_ref(second))
    handle = resolver.resolve(graph_snapshot_ref(first))
    assert resolver.snapshot_for_planning(handle) == first


def test_resolver_rejects_ancestor_symbolic_link_alias(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    path = real_root / "graph" / "canonical.sqlite3"
    _current_snapshot(path)
    alias = tmp_path / "alias"
    alias.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(AgenticGraphHeadError, match="symbolic-link"):
        CurrentGraphHeadResolver(
            alias / "graph" / "canonical.sqlite3",
            campaign_id=CAMPAIGN,
        )


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_descriptor_read_rejects_any_sqlite_sidecar(
    tmp_path: Path,
    suffix: str,
) -> None:
    path = tmp_path / "sidecar" / "canonical.sqlite3"
    snapshot = _current_snapshot(path)
    resolver = CurrentGraphHeadResolver(path, campaign_id=CAMPAIGN)
    handle = resolver.resolve(graph_snapshot_ref(snapshot))
    Path(f"{path}{suffix}").write_bytes(b"untrusted-sidecar")

    with pytest.raises(AgenticGraphHeadError, match="verification failed") as raised:
        resolver.snapshot_for_planning(handle)
    assert isinstance(raised.value.__cause__, Exception)
    assert "requires absent journal and WAL sidecars" in str(raised.value.__cause__)


def test_descriptor_read_rejects_transient_sidecar_churn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "transient-sidecar" / "canonical.sqlite3"
    snapshot = _current_snapshot(path)
    resolver = CurrentGraphHeadResolver(path, campaign_id=CAMPAIGN)
    handle = resolver.resolve(graph_snapshot_ref(snapshot))
    original_verifier = sqlite_store._verified_current_snapshot_from_connection

    def verify_after_transient_sidecar(
        connection: object,
        *,
        campaign_id: str,
        snapshot_id: str,
    ) -> object:
        sidecar = Path(f"{path}-journal")
        sidecar.write_bytes(b"transient-untrusted-sidecar")
        sidecar.unlink()
        return original_verifier(
            connection,  # type: ignore[arg-type]
            campaign_id=campaign_id,
            snapshot_id=snapshot_id,
        )

    monkeypatch.setattr(
        sqlite_store,
        "_verified_current_snapshot_from_connection",
        verify_after_transient_sidecar,
    )

    with pytest.raises(AgenticGraphHeadError, match="verification failed") as raised:
        resolver.snapshot_for_planning(handle)
    assert isinstance(raised.value.__cause__, Exception)
    assert "parent changed" in str(raised.value.__cause__)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode contract")
@pytest.mark.parametrize("drift", ["database", "parent"])
def test_resolver_rejects_public_permission_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    path = tmp_path / drift / "canonical.sqlite3"
    snapshot = _current_snapshot(path)
    resolver = CurrentGraphHeadResolver(path, campaign_id=CAMPAIGN)
    handle = resolver.resolve(graph_snapshot_ref(snapshot))
    changed = path if drift == "database" else path.parent
    changed.chmod(0o666 if drift == "database" else 0o777)

    with pytest.raises(AgenticGraphHeadError, match="owner-only"):
        resolver.snapshot_for_planning(handle)
    with pytest.raises(AgenticGraphHeadError, match="owner-only"):
        CurrentGraphHeadResolver(path, campaign_id=CAMPAIGN)
