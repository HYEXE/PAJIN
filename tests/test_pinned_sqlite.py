from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.graph.sqlite_store import (
    SQLiteGraphStore,
    load_verified_graph_snapshot_history,
)
from pajin.runtime.pinned_sqlite import (
    PinnedMemorySQLite,
    PinnedSQLiteCheckpoint,
    PinnedSQLiteError,
    load_verified_pinned_sqlite_checkpoint_chain,
    load_verified_pinned_sqlite_database,
    pinned_memory_sqlite_for_path,
)
from pajin.runtime.pinned_workspace import PinnedOutputRoot
from pajin.web_assessment import governed
from pajin.web_assessment.governed_adapter_profile import (
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.governed_campaign_evidence import (
    GovernedWebCampaignParentWriter,
    begin_governed_web_campaign_parent,
)
from pajin.web_assessment.governed_models import (
    WebAssessmentCapabilityGrantConsumptionStore,
)

_SCHEMA_DIGEST = "a" * 64
_OWNER = object()
_PATH = Path("authority/governed-web.sqlite3")
_STORE_KIND = "governed-web-graph"
_CAMPAIGN_ID = "juice-shop-governed-local"


def _test_checkpoint_metadata(connection: sqlite3.Connection) -> dict[str, object]:
    rows = connection.execute(
        """
        SELECT name, type
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        ORDER BY type, name
        """
    ).fetchall()
    return {"schemaObjects": [[str(row[0]), str(row[1])] for row in rows]}


def _writer(output_root: Path) -> GovernedWebCampaignParentWriter:
    now = governed._now_utc()
    run_plan = governed._GovernedWebCampaignRunPlan.create()
    profile = production_governed_web_adapter_profile_registry().resolve(
        adapter_reference=governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
        origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
    )
    trust = governed._prepare_governed_web_ephemeral_trust(
        profile=profile,
        now=now,
    )
    writer = begin_governed_web_campaign_parent(
        output_root,
        planned_runs=run_plan.evidence_plan(),
        trust_material=trust.public_trust_material,
        started_at=now,
        signer_not_after=now + timedelta(hours=1),
    )
    with governed._activate_governed_web_campaign_progress_sink(lambda _item: None):
        governed._emit_governed_web_campaign_sealed_progress(
            writer,
            previous_parent_root_digest=None,
            stage="initial",
            status="prepared",
            terminal=False,
        )
        governed._begin_campaign_stage(writer, "provisioning", {})
    return writer


def _checkpoint_observer(
    writer: GovernedWebCampaignParentWriter,
    *,
    store_kind: str,
    observed: list[object] | None = None,
):
    journal = governed._GovernedWebDatabaseCheckpointJournal(writer)

    def record(checkpoint: PinnedSQLiteCheckpoint) -> None:
        with governed._activate_governed_web_campaign_progress_sink(lambda _item: None):
            if store_kind == "governed-web-graph":
                journal.graph_checkpoint(checkpoint)
            else:
                journal.grant_checkpoint(checkpoint)
        if observed is not None:
            observed.append(checkpoint)

    return record


def _database(
    writer: GovernedWebCampaignParentWriter,
    *,
    checkpoint_observer=None,
) -> PinnedMemorySQLite:
    return PinnedMemorySQLite.create(
        _PATH,
        store_kind=_STORE_KIND,
        campaign_id=_CAMPAIGN_ID,
        schema_digest=_SCHEMA_DIGEST,
        max_bytes=1024 * 1024,
        owner_authority=_OWNER,
        checkpoint_metadata=_test_checkpoint_metadata,
        checkpoint_observer=(
            checkpoint_observer
            if checkpoint_observer is not None
            else _checkpoint_observer(writer, store_kind=_STORE_KIND)
        ),
        fresh_authority=writer.issue_database_fresh_authority(
            _PATH,
            store_kind=_STORE_KIND,
        ),
    )


def test_pinned_memory_sqlite_publishes_only_after_freeze(tmp_path: Path) -> None:
    output = tmp_path / "output"
    with PinnedOutputRoot.create(output) as root, root.activate():
        database = _database(_writer(Path(".")))
        try:
            with database.connection(
                readonly=False,
                owner_authority=_OWNER,
            ) as connection:
                connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
                connection.execute("INSERT INTO records VALUES ('retained')")
            assert not _PATH.exists()
            checkpoint = database.latest_checkpoint(owner_authority=_OWNER)
            assert checkpoint.ordinal == 1
            assert checkpoint.previous_manifest_digest is None
            assert Path(checkpoint.database_reference).is_file()
            assert Path(checkpoint.manifest_reference).is_file()

            publication = database.freeze_and_publish(owner_authority=_OWNER)

            assert publication.reference == _PATH.as_posix()
            assert publication.size > 0
            assert len(publication.sha256) == 64
            assert not tuple(Path(".").glob(".pajin-sqlite-*.staging"))
            assert not tuple(Path("authority").glob("governed-web.sqlite3-*"))
            with sqlite3.connect(
                f"file:{(output / publication.reference).as_posix()}?mode=ro",
                uri=True,
            ) as connection:
                assert connection.execute("SELECT value FROM records").fetchall() == [
                    ("retained",)
                ]
        finally:
            database.close(owner_authority=_OWNER)


def test_pinned_memory_sqlite_freeze_is_idempotent_and_write_terminal(
    tmp_path: Path,
) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as root, root.activate():
        database = _database(_writer(Path(".")))
        try:
            with database.connection(
                readonly=False,
                owner_authority=_OWNER,
            ) as connection:
                connection.execute("CREATE TABLE records (value INTEGER NOT NULL)")
            first = database.freeze_and_publish(owner_authority=_OWNER)
            assert database.freeze_and_publish(owner_authority=_OWNER) == first
            with (
                pytest.raises(PinnedSQLiteError, match="frozen"),
                database.connection(readonly=False, owner_authority=_OWNER),
            ):
                pass
            with database.connection(
                readonly=True,
                owner_authority=_OWNER,
            ) as connection:
                rows = connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
                assert [tuple(row) for row in rows] == [("records",)]
        finally:
            database.close(owner_authority=_OWNER)


def test_pinned_memory_sqlite_rejects_foreign_live_authority(tmp_path: Path) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as root, root.activate():
        database = _database(_writer(Path(".")))
        foreign = object()
        try:
            with pytest.raises(PinnedSQLiteError, match="owner authority"):
                pinned_memory_sqlite_for_path(
                    database.path,
                    owner_authority=foreign,
                )
            with (
                pytest.raises(PinnedSQLiteError, match="owner authority"),
                database.connection(readonly=False, owner_authority=foreign),
            ):
                pass
            with pytest.raises(PinnedSQLiteError, match="owner authority"):
                database.freeze_and_publish(owner_authority=foreign)
            with pytest.raises(PinnedSQLiteError, match="owner authority"):
                database.close(owner_authority=foreign)
            assert not _PATH.exists()
            with database.connection(
                readonly=False,
                owner_authority=_OWNER,
            ) as connection:
                connection.execute("CREATE TABLE retained (value INTEGER NOT NULL)")
        finally:
            database.close(owner_authority=_OWNER)


def test_pinned_memory_sqlite_rejects_parent_swap_without_victim_write(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    victim = tmp_path / "victim"
    victim.mkdir(mode=0o700)
    sentinel = victim / "sentinel.txt"
    sentinel.write_text("unchanged")
    with PinnedOutputRoot.create(output) as root, root.activate():
        database = _database(_writer(Path(".")))
        parked = Path("authority-parked")
        try:
            with (
                pytest.raises(PinnedSQLiteError, match="parent link changed"),
                database.connection(
                    readonly=False,
                    owner_authority=_OWNER,
                ) as connection,
            ):
                connection.execute("CREATE TABLE records (value INTEGER NOT NULL)")
                Path("authority").rename(parked)
                Path("authority").symlink_to(victim, target_is_directory=True)
            assert sentinel.read_text() == "unchanged"
            assert tuple(victim.iterdir()) == (sentinel,)
            with pytest.raises(PinnedSQLiteError):
                database.freeze_and_publish(owner_authority=_OWNER)
        finally:
            if Path("authority").is_symlink():
                Path("authority").unlink()
            if parked.exists():
                parked.rename("authority")
            database.close(owner_authority=_OWNER)


def test_pinned_memory_sqlite_rejects_final_leaf_symlink_without_victim_write(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    victim = tmp_path / "victim.sqlite3"
    victim.write_bytes(b"protected")
    with PinnedOutputRoot.create(output) as root, root.activate():
        database = _database(_writer(Path(".")))
        try:
            with database.connection(
                readonly=False,
                owner_authority=_OWNER,
            ) as connection:
                connection.execute("CREATE TABLE records (value INTEGER NOT NULL)")
            _PATH.symlink_to(victim)
            with pytest.raises(FileExistsError):
                database.freeze_and_publish(owner_authority=_OWNER)
            assert victim.read_bytes() == b"protected"
            assert _PATH.is_symlink()
            assert not tuple(Path("authority").glob(".*.staging-*"))
        finally:
            database.close(owner_authority=_OWNER)


def test_pinned_memory_sqlite_detects_swap_during_no_replace_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    victim = tmp_path / "victim"
    victim.mkdir(mode=0o700)
    sentinel = victim / "sentinel.txt"
    sentinel.write_text("unchanged")
    with PinnedOutputRoot.create(output) as root, root.activate():
        database = _database(_writer(Path(".")))
        parked = Path("authority-parked")
        real_link = os.link

        def swap_then_link(
            source: str,
            destination: str,
            *,
            src_dir_fd: int,
            dst_dir_fd: int,
            follow_symlinks: bool,
        ) -> None:
            Path("authority").rename(parked)
            Path("authority").symlink_to(victim, target_is_directory=True)
            real_link(
                source,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
                follow_symlinks=follow_symlinks,
            )

        try:
            with database.connection(
                readonly=False,
                owner_authority=_OWNER,
            ) as connection:
                connection.execute("CREATE TABLE records (value INTEGER NOT NULL)")
            monkeypatch.setattr(os, "link", swap_then_link)
            with pytest.raises(PinnedSQLiteError, match="parent link changed"):
                database.freeze_and_publish(owner_authority=_OWNER)
            assert sentinel.read_text() == "unchanged"
            assert tuple(victim.iterdir()) == (sentinel,)
            assert not (parked / "governed-web.sqlite3").exists()
        finally:
            monkeypatch.setattr(os, "link", real_link)
            if Path("authority").is_symlink():
                Path("authority").unlink()
            if parked.exists():
                parked.rename("authority")
            database.close(owner_authority=_OWNER)


def test_pinned_memory_sqlite_requires_active_workspace_and_exact_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(PinnedSQLiteError, match="active pinned workspace"):
        PinnedMemorySQLite.create(
            _PATH,
            store_kind=_STORE_KIND,
            campaign_id=_CAMPAIGN_ID,
            schema_digest=_SCHEMA_DIGEST,
            max_bytes=1024 * 1024,
            owner_authority=_OWNER,
            checkpoint_metadata=_test_checkpoint_metadata,
            checkpoint_observer=lambda _checkpoint: None,
            fresh_authority=object(),
        )

    with PinnedOutputRoot.create(tmp_path / "output") as root, root.activate():
        with pytest.raises(ValueError, match="one parent"):
            PinnedMemorySQLite.create(
                Path("too/deep/state.sqlite3"),
                store_kind="test-authority",
                campaign_id="campaign-test",
                schema_digest=_SCHEMA_DIGEST,
                max_bytes=1024 * 1024,
                owner_authority=_OWNER,
                checkpoint_metadata=_test_checkpoint_metadata,
                checkpoint_observer=lambda _checkpoint: None,
                fresh_authority=object(),
            )
        database = _database(_writer(Path(".")))
        try:
            assert pinned_memory_sqlite_for_path(
                database.path,
                owner_authority=_OWNER,
            ) is database
            with pytest.raises(FileExistsError, match="already registered"):
                _database(_writer(Path(".")))
        finally:
            database.close(owner_authority=_OWNER)


def test_pinned_memory_sqlite_requires_one_use_sealed_parent_fresh_authority(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    path = _PATH
    with PinnedOutputRoot.create(output) as root, root.activate():
        with pytest.raises(PinnedSQLiteError, match="sealed-parent fresh authority"):
            PinnedMemorySQLite.create(
                path,
                store_kind=_STORE_KIND,
                campaign_id=_CAMPAIGN_ID,
                schema_digest=_SCHEMA_DIGEST,
                max_bytes=1024 * 1024,
                owner_authority=_OWNER,
                checkpoint_metadata=_test_checkpoint_metadata,
                checkpoint_observer=lambda _checkpoint: None,
                fresh_authority=object(),
            )
        assert not Path("authority").exists()

        writer = _writer(Path("."))
        fresh = writer.issue_database_fresh_authority(
            path,
            store_kind=_STORE_KIND,
        )
        database = PinnedMemorySQLite.create(
            path,
            store_kind=_STORE_KIND,
            campaign_id=_CAMPAIGN_ID,
            schema_digest=_SCHEMA_DIGEST,
            max_bytes=1024 * 1024,
            owner_authority=_OWNER,
            checkpoint_metadata=_test_checkpoint_metadata,
            checkpoint_observer=_checkpoint_observer(
                writer,
                store_kind=_STORE_KIND,
            ),
            fresh_authority=fresh,
        )
        database.close(owner_authority=_OWNER)
        with pytest.raises(PinnedSQLiteError, match="differs or was consumed"):
            PinnedMemorySQLite.create(
                path,
                store_kind=_STORE_KIND,
                campaign_id=_CAMPAIGN_ID,
                schema_digest=_SCHEMA_DIGEST,
                max_bytes=1024 * 1024,
                owner_authority=_OWNER,
                checkpoint_metadata=_test_checkpoint_metadata,
                checkpoint_observer=lambda _checkpoint: None,
                fresh_authority=fresh,
            )


def test_pinned_memory_sqlite_detects_deleted_live_checkpoint_before_more_work(
    tmp_path: Path,
) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as root, root.activate():
        database = _database(_writer(Path(".")))
        try:
            with database.connection(
                readonly=False,
                owner_authority=_OWNER,
            ) as connection:
                connection.execute("CREATE TABLE retained (value INTEGER NOT NULL)")
            checkpoint = database.latest_checkpoint(owner_authority=_OWNER)
            Path(checkpoint.database_reference).unlink()
            Path(checkpoint.manifest_reference).unlink()
            before = tuple(Path("authority").iterdir())
            with (
                pytest.raises(PinnedSQLiteError, match="published governed"),
                database.connection(readonly=False, owner_authority=_OWNER),
            ):
                pass
            assert tuple(Path("authority").iterdir()) == before
            assert not _PATH.exists()
        finally:
            database.close(owner_authority=_OWNER)


def test_pinned_memory_sqlite_rejects_casefold_collision(tmp_path: Path) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as root, root.activate():
        Path("Authority").mkdir(mode=0o700)
        with pytest.raises(FileExistsError, match="case-fold"):
            _database(_writer(Path(".")))


def test_pinned_memory_sqlite_refuses_to_fork_incomplete_checkpoint_lineage(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    with PinnedOutputRoot.create(output) as root, root.activate():
        database = _database(_writer(Path(".")))
        with database.connection(
            readonly=False,
            owner_authority=_OWNER,
        ) as connection:
            connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
            connection.execute("INSERT INTO records VALUES ('branch-a')")
        checkpoint = database.latest_checkpoint(owner_authority=_OWNER)
        manifest_path = Path(checkpoint.manifest_reference)
        database_path = Path(checkpoint.database_reference)
        manifest = json.loads(manifest_path.read_bytes())
        before = {
            path.name: sha256(path.read_bytes()).hexdigest()
            for path in Path("authority").iterdir()
        }
        database.close(owner_authority=_OWNER)

        assert manifest["manifestDigest"] == checkpoint.manifest_digest
        assert manifest["ordinal"] == 1
        assert manifest["previousManifestDigest"] is None
        assert manifest["databaseReference"] == checkpoint.database_reference
        assert manifest["databaseSha256"] == checkpoint.database_sha256
        with sqlite3.connect(
            f"file:{(output / database_path).as_posix()}?mode=ro",
            uri=True,
        ) as connection:
            assert connection.execute("SELECT value FROM records").fetchall() == [
                ("branch-a",)
            ]

        with pytest.raises(PinnedSQLiteError, match="already permanently enrolled"):
            _database(_writer(Path(".")))
        after = {
            path.name: sha256(path.read_bytes()).hexdigest()
            for path in Path("authority").iterdir()
        }
        assert after == before
        assert not _PATH.exists()


def test_pinned_memory_sqlite_checkpoint_observer_is_synchronous_and_chained(
    tmp_path: Path,
) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as root, root.activate():
        writer = _writer(Path("."))
        raw_observed: list[object] = []
        database = _database(
            writer,
            checkpoint_observer=_checkpoint_observer(
                writer,
                store_kind=_STORE_KIND,
                observed=raw_observed,
            ),
        )
        try:
            with database.connection(
                readonly=False,
                owner_authority=_OWNER,
            ) as connection:
                connection.execute("CREATE TABLE first (value INTEGER NOT NULL)")
            first = database.latest_checkpoint(owner_authority=_OWNER)
            with database.connection(
                readonly=False,
                owner_authority=_OWNER,
            ) as connection:
                connection.execute("CREATE TABLE second (value INTEGER NOT NULL)")
            second = database.latest_checkpoint(owner_authority=_OWNER)
            observed = [
                (checkpoint.ordinal, checkpoint.previous_manifest_digest)
                for checkpoint in raw_observed
            ]
            assert observed == [(1, None), (2, first.manifest_digest)]
            assert second.previous_manifest_digest == first.manifest_digest
        finally:
            database.close(owner_authority=_OWNER)


def test_pinned_memory_sqlite_observer_rejection_is_terminal_after_checkpoint(
    tmp_path: Path,
) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as root, root.activate():
        writer = _writer(Path("."))

        def reject_checkpoint(_: object) -> None:
            raise RuntimeError("parent ACK rejected")

        database = _database(writer, checkpoint_observer=reject_checkpoint)
        try:
            with (
                pytest.raises(RuntimeError, match="parent ACK rejected"),
                database.connection(readonly=False, owner_authority=_OWNER) as connection,
            ):
                connection.execute("CREATE TABLE retained (value INTEGER NOT NULL)")
            checkpoint = database.latest_checkpoint(owner_authority=_OWNER)
            assert Path(checkpoint.database_reference).is_file()
            assert Path(checkpoint.manifest_reference).is_file()
            with (
                pytest.raises(PinnedSQLiteError, match="frozen"),
                database.connection(readonly=False, owner_authority=_OWNER),
            ):
                pass
            with pytest.raises(PinnedSQLiteError, match="terminal checkpoint"):
                database.freeze_and_publish(owner_authority=_OWNER)
            assert not _PATH.exists()
        finally:
            database.close(owner_authority=_OWNER)


def test_pinned_memory_sqlite_rejects_noop_checkpoint_observer(
    tmp_path: Path,
) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as root, root.activate():
        writer = _writer(Path("."))
        database = _database(writer, checkpoint_observer=lambda _checkpoint: None)
        try:
            with (
                pytest.raises(PinnedSQLiteError, match="lacks its sealed external ACK"),
                database.connection(readonly=False, owner_authority=_OWNER) as connection,
            ):
                connection.execute("CREATE TABLE retained (value INTEGER NOT NULL)")
            checkpoint = database.latest_checkpoint(owner_authority=_OWNER)
            assert Path(checkpoint.database_reference).is_file()
            assert Path(checkpoint.manifest_reference).is_file()
            with pytest.raises(PinnedSQLiteError, match="terminal checkpoint"):
                database.freeze_and_publish(owner_authority=_OWNER)
            assert not _PATH.exists()
        finally:
            database.close(owner_authority=_OWNER)


def test_pinned_memory_sqlite_enrollment_blocks_fresh_branch_after_parent_relocation(
    tmp_path: Path,
) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as root, root.activate():
        database = _database(_writer(Path(".")))
        with database.connection(
            readonly=False,
            owner_authority=_OWNER,
        ) as connection:
            connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
            connection.execute("INSERT INTO records VALUES ('branch-a')")
        database.close(owner_authority=_OWNER)

        parked = Path("authority-branch-a")
        Path("authority").rename(parked)
        try:
            with pytest.raises(PinnedSQLiteError, match="already permanently enrolled"):
                _database(_writer(Path(".")))
            assert not _PATH.exists()
            assert (parked / "governed-web.sqlite3").exists() is False
        finally:
            if Path("authority").exists():
                Path("authority").rmdir()
            parked.rename("authority")


def test_verified_pinned_sqlite_loader_requires_exact_complete_chain_and_inventory(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    with PinnedOutputRoot.create(output) as root, root.activate():
        database = _database(_writer(Path(".")))
        try:
            with database.connection(
                readonly=False,
                owner_authority=_OWNER,
            ) as connection:
                connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
            with database.connection(
                readonly=False,
                owner_authority=_OWNER,
            ) as connection:
                connection.execute("INSERT INTO records VALUES ('retained')")
            head = database.latest_checkpoint(owner_authority=_OWNER)
            checkpoint_chain = load_verified_pinned_sqlite_checkpoint_chain(
                output,
                final_database_reference=_PATH.as_posix(),
                expected_store_kind=_STORE_KIND,
                expected_campaign_id=_CAMPAIGN_ID,
                expected_schema_digest=_SCHEMA_DIGEST,
                expected_latest_manifest_reference=head.manifest_reference,
                expected_latest_manifest_digest=head.manifest_digest,
                expected_latest_ordinal=head.ordinal,
                expected_latest_database_sha256=head.database_sha256,
                max_database_bytes=1024 * 1024,
            )
            assert checkpoint_chain.latest_checkpoint == head
            enrollment_publication = database.enrollment_publication(
                owner_authority=_OWNER
            )
            publication = database.freeze_and_publish(owner_authority=_OWNER)
        finally:
            database.close(owner_authority=_OWNER)

        verified = load_verified_pinned_sqlite_database(
            output,
            final_database_reference=publication.reference,
            expected_store_kind=_STORE_KIND,
            expected_campaign_id=_CAMPAIGN_ID,
            expected_schema_digest=_SCHEMA_DIGEST,
            expected_latest_manifest_reference=head.manifest_reference,
            expected_latest_manifest_digest=head.manifest_digest,
            expected_latest_ordinal=head.ordinal,
            expected_final_database_sha256=publication.sha256,
            expected_enrollment_reference=enrollment_publication.reference,
            expected_enrollment_sha256=enrollment_publication.sha256,
            expected_enrollment_size=enrollment_publication.size,
            max_database_bytes=1024 * 1024,
        )
        assert [item.ordinal for item in verified.checkpoints] == [1, 2]
        assert verified.latest_checkpoint == head
        assert verified.final_publication == publication
        assert verified.enrollment_publication == enrollment_publication
        assert verified.database_bytes == (output / publication.reference).read_bytes()

        with pytest.raises(PinnedSQLiteError, match="enrollment publication differs"):
            load_verified_pinned_sqlite_database(
                output,
                final_database_reference=publication.reference,
                expected_store_kind=_STORE_KIND,
                expected_campaign_id=_CAMPAIGN_ID,
                expected_schema_digest=_SCHEMA_DIGEST,
                expected_latest_manifest_reference=head.manifest_reference,
                expected_latest_manifest_digest=head.manifest_digest,
                expected_latest_ordinal=head.ordinal,
                expected_final_database_sha256=publication.sha256,
                expected_enrollment_reference=enrollment_publication.reference,
                expected_enrollment_sha256="b" * 64,
                expected_enrollment_size=enrollment_publication.size,
                max_database_bytes=1024 * 1024,
            )

        extra = Path("authority") / (
            ".governed-web.sqlite3.checkpoint-00000001-" + "c" * 64 + ".json"
        )
        extra.write_bytes(b"{}\n")
        extra.chmod(0o600)
        with pytest.raises(PinnedSQLiteError, match="inventory"):
            load_verified_pinned_sqlite_database(
                output,
                final_database_reference=publication.reference,
                expected_store_kind=_STORE_KIND,
                expected_campaign_id=_CAMPAIGN_ID,
                expected_schema_digest=_SCHEMA_DIGEST,
                expected_latest_manifest_reference=head.manifest_reference,
                expected_latest_manifest_digest=head.manifest_digest,
                expected_latest_ordinal=head.ordinal,
                expected_final_database_sha256=publication.sha256,
                expected_enrollment_reference=enrollment_publication.reference,
                expected_enrollment_sha256=enrollment_publication.sha256,
                expected_enrollment_size=enrollment_publication.size,
                max_database_bytes=1024 * 1024,
            )


def test_verified_pinned_sqlite_loader_rejects_modified_enrollment(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    with PinnedOutputRoot.create(output) as root, root.activate():
        database = _database(_writer(Path(".")))
        try:
            with database.connection(
                readonly=False,
                owner_authority=_OWNER,
            ) as connection:
                connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
            head = database.latest_checkpoint(owner_authority=_OWNER)
            enrollment_publication = database.enrollment_publication(
                owner_authority=_OWNER
            )
            publication = database.freeze_and_publish(owner_authority=_OWNER)
        finally:
            database.close(owner_authority=_OWNER)

        enrollment, = Path(".").glob(".pajin-governed-sqlite-enrollment-v1-*.json")
        enrollment.write_bytes(enrollment.read_bytes()[:-1] + b" ")
        with pytest.raises(PinnedSQLiteError, match="enrollment"):
            load_verified_pinned_sqlite_database(
                output,
                final_database_reference=publication.reference,
                expected_store_kind=_STORE_KIND,
                expected_campaign_id=_CAMPAIGN_ID,
                expected_schema_digest=_SCHEMA_DIGEST,
                expected_latest_manifest_reference=head.manifest_reference,
                expected_latest_manifest_digest=head.manifest_digest,
                expected_latest_ordinal=head.ordinal,
                expected_final_database_sha256=publication.sha256,
                expected_enrollment_reference=enrollment_publication.reference,
                expected_enrollment_sha256=enrollment_publication.sha256,
                expected_enrollment_size=enrollment_publication.size,
                max_database_bytes=1024 * 1024,
            )


@pytest.mark.parametrize("store", ["graph", "grant"])
def test_never_governed_exact_database_name_remains_ordinary_writable_namespace(
    tmp_path: Path,
    store: str,
) -> None:
    authority = tmp_path / "ordinary" / "authority"
    authority.mkdir(parents=True, mode=0o700)
    if store == "graph":
        path = authority / "governed-web.sqlite3"
        graph = SQLiteGraphStore(path, campaign_id=_CAMPAIGN_ID)
        assert graph.projection_store.current().revision == 0
    else:
        path = authority / "capability-grant-consumptions.sqlite3"
        grant = WebAssessmentCapabilityGrantConsumptionStore(
            path,
            campaign_id=_CAMPAIGN_ID,
        )
        assert grant.receipt_for_grant("grant-test") is None
    assert path.is_file()


def test_sqlite_graph_store_governed_memory_factory_publishes_valid_database(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    path = Path("authority/governed-web.sqlite3")
    with PinnedOutputRoot.create(output) as root, root.activate():
        writer = _writer(Path("."))
        observed: list[object] = []
        store, authority = SQLiteGraphStore.create_governed_in_memory(
            path,
            campaign_id=_CAMPAIGN_ID,
            fresh_authority=writer.issue_database_fresh_authority(
                path,
                store_kind="governed-web-graph",
            ),
            checkpoint_observer=_checkpoint_observer(
                writer,
                store_kind="governed-web-graph",
                observed=observed,
            ),
        )
        try:
            assert store.projection_store.current().revision == 0
            assert not path.exists()
            publication = authority.freeze_and_publish()
            assert publication.reference == path.as_posix()
            assert path.is_file()
        finally:
            authority.close()

        before = {
            item.name: sha256(item.read_bytes()).hexdigest()
            for item in Path("authority").iterdir()
        }
        with pytest.raises(Exception, match="historical and never writable"):
            SQLiteGraphStore(path, campaign_id=_CAMPAIGN_ID)
        assert {
            item.name: sha256(item.read_bytes()).hexdigest()
            for item in Path("authority").iterdir()
        } == before
        assert load_verified_graph_snapshot_history(
            path,
            campaign_id=_CAMPAIGN_ID,
        ) == ()
        assert observed
        assert not tuple(Path("authority").glob("governed-web.sqlite3-*"))


def test_web_grant_store_governed_memory_factory_publishes_valid_database(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    path = Path("authority/capability-grant-consumptions.sqlite3")
    with PinnedOutputRoot.create(output) as root, root.activate():
        writer = _writer(Path("."))
        observed: list[object] = []
        store, authority = (
            WebAssessmentCapabilityGrantConsumptionStore.create_governed_in_memory(
                path,
                campaign_id=_CAMPAIGN_ID,
                fresh_authority=writer.issue_database_fresh_authority(
                    path,
                    store_kind="governed-web-grant",
                ),
                checkpoint_observer=_checkpoint_observer(
                    writer,
                    store_kind="governed-web-grant",
                    observed=observed,
                ),
            )
        )
        try:
            assert store.receipt_for_grant("grant-test") is None
            assert not path.exists()
            publication = authority.freeze_and_publish()
            assert publication.reference == path.as_posix()
            assert path.is_file()
        finally:
            authority.close()

        before = {
            item.name: sha256(item.read_bytes()).hexdigest()
            for item in Path("authority").iterdir()
        }
        with pytest.raises(Exception, match="historical and never writable"):
            WebAssessmentCapabilityGrantConsumptionStore(
                path,
                campaign_id=_CAMPAIGN_ID,
            )
        assert {
            item.name: sha256(item.read_bytes()).hexdigest()
            for item in Path("authority").iterdir()
        } == before
        with sqlite3.connect(
            f"file:{(output / path).as_posix()}?mode=ro",
            uri=True,
        ) as connection:
            assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
            assert connection.execute(
                "SELECT key, value FROM web_capability_grant_consumption_metadata ORDER BY key"
            ).fetchall()[0] == ("campaignId", _CAMPAIGN_ID)
        assert observed
        assert not tuple(Path("authority").glob("capability-grant-consumptions.sqlite3-*"))


@pytest.mark.parametrize("store", ["graph", "grant"])
def test_governed_database_checkpoint_namespace_cannot_fork_after_close(
    tmp_path: Path,
    store: str,
) -> None:
    output = tmp_path / f"{store}-checkpoint-only"
    with PinnedOutputRoot.create(output) as root, root.activate():
        writer = _writer(Path("."))
        observed: list[object] = []
        if store == "graph":
            path = Path("authority/governed-web.sqlite3")
            _, authority = SQLiteGraphStore.create_governed_in_memory(
                path,
                campaign_id=_CAMPAIGN_ID,
                fresh_authority=writer.issue_database_fresh_authority(
                    path,
                    store_kind="governed-web-graph",
                ),
                checkpoint_observer=_checkpoint_observer(
                    writer,
                    store_kind="governed-web-graph",
                    observed=observed,
                ),
            )
        else:
            path = Path("authority/capability-grant-consumptions.sqlite3")
            _, authority = (
                WebAssessmentCapabilityGrantConsumptionStore.create_governed_in_memory(
                    path,
                    campaign_id=_CAMPAIGN_ID,
                    fresh_authority=writer.issue_database_fresh_authority(
                        path,
                        store_kind="governed-web-grant",
                    ),
                    checkpoint_observer=_checkpoint_observer(
                        writer,
                        store_kind="governed-web-grant",
                        observed=observed,
                    ),
                )
            )
        authority.close()
        before = {
            item.name: sha256(item.read_bytes()).hexdigest()
            for item in Path("authority").iterdir()
        }
        assert observed and not path.exists()
        with pytest.raises(Exception, match="historical and never writable"):
            if store == "graph":
                SQLiteGraphStore(path, campaign_id=_CAMPAIGN_ID)
            else:
                WebAssessmentCapabilityGrantConsumptionStore(
                    path,
                    campaign_id=_CAMPAIGN_ID,
                )
        assert not path.exists()
        assert {
            item.name: sha256(item.read_bytes()).hexdigest()
            for item in Path("authority").iterdir()
        } == before


@pytest.mark.parametrize("store", ["graph", "grant"])
def test_governed_published_database_namespace_is_read_only_after_restart(
    tmp_path: Path,
    store: str,
) -> None:
    output = tmp_path / f"{store}-published"
    with PinnedOutputRoot.create(output) as root, root.activate():
        writer = _writer(Path("."))
        observed: list[object] = []
        if store == "graph":
            relative = Path("authority/governed-web.sqlite3")
            _, authority = SQLiteGraphStore.create_governed_in_memory(
                relative,
                campaign_id=_CAMPAIGN_ID,
                fresh_authority=writer.issue_database_fresh_authority(
                    relative,
                    store_kind="governed-web-graph",
                ),
                checkpoint_observer=_checkpoint_observer(
                    writer,
                    store_kind="governed-web-graph",
                    observed=observed,
                ),
            )
        else:
            relative = Path("authority/capability-grant-consumptions.sqlite3")
            _, authority = (
                WebAssessmentCapabilityGrantConsumptionStore.create_governed_in_memory(
                    relative,
                    campaign_id=_CAMPAIGN_ID,
                    fresh_authority=writer.issue_database_fresh_authority(
                        relative,
                        store_kind="governed-web-grant",
                    ),
                    checkpoint_observer=_checkpoint_observer(
                        writer,
                        store_kind="governed-web-grant",
                        observed=observed,
                    ),
                )
            )
        authority.freeze_and_publish()
        authority.close()
    path = output / relative
    before = sha256(path.read_bytes()).hexdigest()
    constructor = (
        "from pajin.graph.sqlite_store import SQLiteGraphStore as S"
        if store == "graph"
        else "from pajin.web_assessment.governed_models import "
        "WebAssessmentCapabilityGrantConsumptionStore as S"
    )
    script = (
        f"{constructor}\n"
        "from pathlib import Path\n"
        "try:\n"
        f"    S(Path({str(path)!r}), campaign_id={_CAMPAIGN_ID!r})\n"
        "except Exception as exc:\n"
        "    raise SystemExit(0 if 'historical and never writable' in str(exc) else 2)\n"
        "raise SystemExit(3)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    assert sha256(path.read_bytes()).hexdigest() == before
