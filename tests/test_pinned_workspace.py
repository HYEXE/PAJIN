from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.runtime.pinned_workspace import (
    PinnedOutputRoot,
    PinnedWorkspaceError,
    active_pinned_workspace_identity,
    pinned_workspace_relative_path,
)
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.web_assessment.governed_gateway import _gateway_run_path_snapshot
from pajin.web_assessment.governed_models import WebAssessmentCapabilityGrantConsumptionStore

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX dirfd capability")


def test_pinned_output_root_keeps_cwd_inode_after_original_path_swap(tmp_path: Path) -> None:
    output = tmp_path / "output"
    parked = tmp_path / "parked"
    victim = tmp_path / "victim"
    victim.mkdir()

    with PinnedOutputRoot.create(output) as pinned, pinned.activate():
        output.rename(parked)
        output.symlink_to(victim, target_is_directory=True)

        Path("artifact.txt").write_text("pinned\n", encoding="utf-8")

        assert active_pinned_workspace_identity() == pinned.identity
        assert (parked / "artifact.txt").read_text(encoding="utf-8") == "pinned\n"
        assert tuple(victim.iterdir()) == ()
        assert not pinned.original_path_identity_matches()
        with pytest.raises(PinnedWorkspaceError, match="restart path"):
            pinned.require_original_path_identity()


def test_pinned_output_root_rejects_run_ancestor_before_creation(tmp_path: Path) -> None:
    run = tmp_path / "existing-run"
    run.mkdir()
    (run / "events.jsonl").write_text("{}\n", encoding="utf-8")
    (run / "run-integrity.jsonl").write_text("{}\n", encoding="utf-8")
    output = run / "nested" / "output"

    with pytest.raises(PinnedWorkspaceError, match="Run root"):
        PinnedOutputRoot.create(output)

    assert not (run / "nested").exists()


def test_pinned_output_root_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)

    with pytest.raises(PinnedWorkspaceError, match="symbolic-link"):
        PinnedOutputRoot.create(alias / "output")

    assert tuple(actual.iterdir()) == ()


def test_pinned_output_root_rejects_casefold_collision(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    (parent / "Output").mkdir()

    with pytest.raises(FileExistsError, match="case-fold"):
        PinnedOutputRoot.create(parent / "output")


def test_pinned_output_root_rejects_parent_traversal(tmp_path: Path) -> None:
    requested = tmp_path / "parent" / ".." / "output"

    with pytest.raises(ValueError, match="parent traversal"):
        PinnedOutputRoot.create(requested)

    assert not (tmp_path / "parent").exists()
    assert not (tmp_path / "output").exists()


def test_public_environment_cannot_activate_pinned_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_PINNED_WORKSPACE", "1")

    assert active_pinned_workspace_identity() is None
    assert pinned_workspace_relative_path(Path("relative"), label="test path") is None


def test_active_pinned_workspace_rejects_absolute_and_parent_paths(tmp_path: Path) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as pinned, pinned.activate():
        with pytest.raises(ValueError, match="below the pinned workspace"):
            pinned_workspace_relative_path(tmp_path / "foreign", label="test path")
        with pytest.raises(ValueError, match="below the pinned workspace"):
            pinned_workspace_relative_path(Path("safe/../foreign"), label="test path")


def test_active_pinned_workspace_is_process_visible_without_blocking_threads(
    tmp_path: Path,
) -> None:
    observed: list[object] = []

    with PinnedOutputRoot.create(tmp_path / "output") as pinned, pinned.activate():
        thread = threading.Thread(
            target=lambda: observed.append(active_pinned_workspace_identity()),
        )
        thread.start()
        thread.join(timeout=2)

        assert not thread.is_alive()
        assert observed == [pinned.identity]


def test_pinned_output_root_verifies_unchanged_restart_path(tmp_path: Path) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as pinned:
        assert pinned.original_path_identity_matches()
        pinned.require_original_path_identity()


def test_pinned_output_root_identity_includes_owner_and_mode(tmp_path: Path) -> None:
    output = tmp_path / "output"

    with PinnedOutputRoot.create(output) as pinned:
        metadata = output.stat()
        assert pinned.identity.uid == metadata.st_uid
        assert pinned.identity.mode == metadata.st_mode

        output.chmod(0o755)

        assert not pinned.original_path_identity_matches()
        with pytest.raises(PinnedWorkspaceError, match="restart path"):
            pinned.require_original_path_identity()


def test_run_and_sqlite_stores_stay_on_pinned_cwd_after_path_swap(tmp_path: Path) -> None:
    output = tmp_path / "output"
    parked = tmp_path / "parked"
    victim = tmp_path / "victim"
    victim.mkdir()

    with PinnedOutputRoot.create(output) as pinned, pinned.activate():
        output.rename(parked)
        output.symlink_to(victim, target_is_directory=True)

        run = RunStore.create(Path("runs"), "pinned-campaign")
        run.append_event("pinned.started")
        run.write_text_create_only("evidence/result.txt", "parked only")
        seal = run.seal()
        graph = SQLiteGraphStore(
            Path("authority/graph.sqlite3"),
            campaign_id="pinned-campaign",
        )
        grants = WebAssessmentCapabilityGrantConsumptionStore(
            Path("authority/grants.sqlite3"),
            campaign_id="pinned-campaign",
        )

        assert not run.path.is_absolute()
        assert not graph.path.is_absolute()
        assert not grants._path.is_absolute()
        assert verify_run_integrity(run.path).root_digest == seal.root_digest
        assert graph.event_log.events() == ()
        assert tuple(victim.iterdir()) == ()
        assert (parked / "authority/graph.sqlite3").is_file()
        assert (parked / "authority/grants.sqlite3").is_file()


def test_normal_mode_keeps_absolute_store_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    run = RunStore.create(Path("normal-runs"), "normal-campaign")
    graph = SQLiteGraphStore(
        Path("normal-authority/graph.sqlite3"),
        campaign_id="normal-campaign",
    )

    assert run.path.is_absolute()
    assert graph.path.is_absolute()


def test_gateway_run_snapshot_stays_on_renamed_pinned_root(tmp_path: Path) -> None:
    output = tmp_path / "output"
    parked = tmp_path / "parked"
    victim = tmp_path / "victim"
    victim.mkdir()

    with PinnedOutputRoot.create(output) as pinned, pinned.activate():
        output.rename(parked)
        output.symlink_to(victim, target_is_directory=True)
        run = RunStore.create(Path("gateway-runs"), "web-source-gateway")

        path, run_identity, parent_identity = _gateway_run_path_snapshot(run.path)
        repeated = _gateway_run_path_snapshot(path)

        assert path == run.path
        assert repeated == (path, run_identity, parent_identity)
        assert tuple(victim.iterdir()) == ()
        assert (parked / run.path).is_dir()
