from __future__ import annotations

import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path

import pytest

import pajin.control_plane.artifacts as artifact_module
from pajin.control_plane.artifacts import (
    ArtifactConflict,
    ArtifactNotFound,
    ArtifactRepositoryError,
    ArtifactRepositoryLimits,
    ArtifactValidationError,
    ManagedArtifactRepository,
)
from pajin.runtime.store import RunStore

_PRODUCER_RUN_ID = f"run_{'a' * 32}"
_MEDIA_TYPE = "application/x-pajin-run"
_SCHEMA_KIND = "pajin.run.v1"


def _stage_id(character: str = "1") -> str:
    return f"stage_{character * 32}"


def _sealed_run(
    staging_root: Path,
    *,
    staging_id: str = _stage_id(),
    result: str = "sealed-result",
    result_path: str = "result.txt",
    run_id: str = "engine_run_1",
) -> RunStore:
    path = staging_root / staging_id
    path.mkdir(parents=True)
    store = RunStore(run_id=run_id, path=path)
    store.evidence_path.mkdir()
    store.append_event("run.started", {"source": "artifact-test"})
    store.write_text(result_path, result)
    store.append_event("run.completed", {"result": result_path})
    store.seal()
    return store


def _repository(
    tmp_path: Path,
    *,
    limits: ArtifactRepositoryLimits | None = None,
) -> tuple[ManagedArtifactRepository, Path, Path]:
    staging_root = tmp_path / "staging"
    repository_root = tmp_path / "repository"
    staging_root.mkdir(mode=0o700, parents=True)
    repository_root.mkdir(mode=0o700, parents=True)
    return (
        ManagedArtifactRepository(
            staging_root=staging_root,
            repository_root=repository_root,
            limits=limits,
        ),
        staging_root,
        repository_root,
    )


def _import(
    repository: ManagedArtifactRepository,
    *,
    staging_id: str = _stage_id(),
    producer_run_id: str = _PRODUCER_RUN_ID,
):
    return repository.import_run(
        staging_id=staging_id,
        producer_run_id=producer_run_id,
        media_type=_MEDIA_TYPE,
        schema_kind=_SCHEMA_KIND,
        created_by="worker:test",
    )


def _canonical_tree_digest(root: Path) -> tuple[str, int, list[str]]:
    entries: list[dict[str, object]] = []
    total = 0
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        content = path.read_bytes()
        relative = path.relative_to(root).as_posix()
        total += len(content)
        entries.append(
            {
                "path": relative,
                "sha256": sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    material = json.dumps(
        entries,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(material).hexdigest(), total, [str(item["path"]) for item in entries]


def test_import_copies_and_binds_the_complete_sealed_run_tree(tmp_path: Path) -> None:
    repository, staging_root, repository_root = _repository(tmp_path)
    staged = _sealed_run(staging_root)

    snapshot = _import(repository)
    digest, byte_length, paths = _canonical_tree_digest(snapshot.path)

    assert snapshot.path != staged.path
    assert repository_root in snapshot.path.parents
    assert snapshot.storage_key == f"v1/sha256/{digest}"
    assert snapshot.ref.repository_version == 1
    assert snapshot.ref.content_digest == digest
    assert snapshot.ref.byte_length == byte_length
    assert snapshot.ref.producer_run_id == _PRODUCER_RUN_ID
    assert snapshot.ref.run_id == staged.run_id
    assert set(paths) == {"events.jsonl", "result.txt", "run-integrity.jsonl"}
    assert repository.resolve(snapshot.ref) == snapshot

    (staged.path / "result.txt").write_text("staging changed\n", encoding="utf-8")
    assert (snapshot.path / "result.txt").read_text(encoding="utf-8") == "sealed-result\n"


@pytest.mark.parametrize("mutation", ["empty", "directory", "hard-link", "oversized"])
def test_import_rejects_a_malformed_transient_run_lock(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    lock_path = staged.path / ".pajin-run.lock"
    if mutation == "empty":
        lock_path.write_bytes(b"")
    elif mutation == "directory":
        lock_path.mkdir()
    elif mutation == "hard-link":
        outside = tmp_path / "outside-lock"
        outside.write_bytes(b"")
        os.link(outside, lock_path)
    else:
        lock_path.write_bytes(b"invalid")

    with pytest.raises(ArtifactValidationError, match="mutation lock metadata"):
        _import(repository)


def test_import_normalizes_empty_directories_and_resolve_rejects_new_ones(
    tmp_path: Path,
) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    (staged.path / "unused" / "nested").mkdir(parents=True)

    snapshot = _import(repository)

    assert not (snapshot.path / "evidence").exists()
    assert not (snapshot.path / "unused").exists()
    (snapshot.path / "untracked-empty").mkdir()
    with pytest.raises(ArtifactValidationError, match="canonical file tree"):
        repository.resolve(snapshot.ref)


@pytest.mark.parametrize(
    "staging_id",
    [
        "stage_" + "A" * 32,
        "staging_" + "1" * 32,
        "stage_" + "1" * 31,
        "../stage_" + "1" * 32,
        "/stage_" + "1" * 32,
        "stage_" + "g" * 32,
    ],
)
def test_import_accepts_only_an_opaque_strict_staging_id(tmp_path: Path, staging_id: str) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    _sealed_run(staging_root)

    with pytest.raises(ArtifactValidationError, match="staging_id must match"):
        _import(repository, staging_id=staging_id)

    with pytest.raises(ArtifactNotFound, match="staged Run is missing"):
        _import(repository, staging_id=_stage_id("2"))


def test_staging_reservation_release_is_empty_only_and_idempotent(tmp_path: Path) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    released_id = _stage_id("2")
    occupied_id = _stage_id("3")

    repository.reserve_staging(released_id)
    assert repository.release_staging_reservation(released_id)
    assert not (staging_root / released_id).exists()
    assert not repository.release_staging_reservation(released_id)

    repository.reserve_staging(occupied_id)
    output = staging_root / occupied_id / "worker-output.txt"
    output.write_text("preserve me", encoding="utf-8")
    with pytest.raises(ArtifactConflict, match="contains output"):
        repository.release_staging_reservation(occupied_id)
    assert output.read_text(encoding="utf-8") == "preserve me"


def test_staging_reservation_release_rejects_invalid_or_linked_capabilities(
    tmp_path: Path,
) -> None:
    repository, staging_root, _ = _repository(tmp_path)

    with pytest.raises(ArtifactValidationError, match="staging_id must match"):
        repository.release_staging_reservation("../outside")

    outside = tmp_path / "outside-staging"
    outside.mkdir(mode=0o700)
    linked_id = _stage_id("4")
    (staging_root / linked_id).symlink_to(outside, target_is_directory=True)
    with pytest.raises(ArtifactValidationError, match="real directory"):
        repository.release_staging_reservation(linked_id)
    assert outside.is_dir()
    assert staging_root.joinpath(linked_id).is_symlink()


def test_committed_staged_run_consumption_is_exact_and_idempotent(tmp_path: Path) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    snapshot = _import(repository)

    assert repository.consume_staged_run(
        staging_id=_stage_id(),
        expected_ref=snapshot.ref,
    )
    assert not staged.path.exists()
    assert repository.resolve(snapshot.ref) == snapshot
    assert not repository.consume_staged_run(
        staging_id=_stage_id(),
        expected_ref=snapshot.ref,
    )


def test_staged_run_consumption_requires_the_exact_managed_reference(
    tmp_path: Path,
) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    first = _sealed_run(staging_root)
    first_snapshot = _import(repository)
    second_id = _stage_id("2")
    _sealed_run(
        staging_root,
        staging_id=second_id,
        result="different sealed result",
        run_id="engine_run_2",
    )
    second_snapshot = _import(
        repository,
        staging_id=second_id,
        producer_run_id=f"run_{'b' * 32}",
    )

    with pytest.raises(ArtifactConflict, match="committed Artifact authority"):
        repository.consume_staged_run(
            staging_id=_stage_id(),
            expected_ref=second_snapshot.ref,
        )

    assert first.path.is_dir()
    assert repository.resolve(first_snapshot.ref) == first_snapshot


def test_staged_run_consumption_preserves_content_drift(tmp_path: Path) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    snapshot = _import(repository)
    staged_result = staged.path / "result.txt"
    staged_result.write_text("changed after managed import\n", encoding="utf-8")

    with pytest.raises(ArtifactValidationError, match="integrity verification"):
        repository.consume_staged_run(
            staging_id=_stage_id(),
            expected_ref=snapshot.ref,
        )

    assert staged.path.is_dir()
    assert staged_result.read_text(encoding="utf-8") == "changed after managed import\n"


@pytest.mark.parametrize("mutation", ["symlink", "hard-link"])
def test_staged_run_consumption_never_follows_external_links(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    snapshot = _import(repository)
    outside = tmp_path / "outside.txt"
    outside.write_text("must survive\n", encoding="utf-8")
    if mutation == "symlink":
        (staged.path / "outside-link").symlink_to(outside)
        message = "symbolic links"
    else:
        os.link(outside, staged.path / "outside-hard-link")
        message = "hard-linked"

    with pytest.raises(ArtifactValidationError, match=message):
        repository.consume_staged_run(
            staging_id=_stage_id(),
            expected_ref=snapshot.ref,
        )

    assert outside.read_text(encoding="utf-8") == "must survive\n"
    assert staged.path.is_dir()


def test_concurrent_staged_run_consumption_deletes_exactly_once(tmp_path: Path) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    snapshot = _import(repository)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda _: repository.consume_staged_run(
                    staging_id=_stage_id(),
                    expected_ref=snapshot.ref,
                ),
                range(8),
            )
        )

    assert results.count(True) == 1
    assert results.count(False) == 7
    assert not staged.path.exists()


def test_cross_instance_advisory_lock_serializes_staged_run_consumption(
    tmp_path: Path,
) -> None:
    repository, staging_root, repository_root = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    snapshot = _import(repository)
    peer = ManagedArtifactRepository(
        staging_root=staging_root,
        repository_root=repository_root,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda current: current.consume_staged_run(
                    staging_id=_stage_id(),
                    expected_ref=snapshot.ref,
                ),
                (repository, peer),
            )
        )

    assert sorted(results) == [False, True]
    assert not staged.path.exists()


def test_staged_run_consumption_recovers_a_durable_interrupted_claim(tmp_path: Path) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    snapshot = _import(repository)
    tombstone = staging_root / f".consuming-{_stage_id()}"
    staged.path.rename(tombstone)

    assert repository.consume_staged_run(
        staging_id=_stage_id(),
        expected_ref=snapshot.ref,
    )
    assert not tombstone.exists()
    assert not staged.path.exists()


def test_staged_run_consumption_detects_path_swap_without_external_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    snapshot = _import(repository)
    moved = staging_root / "original-before-race"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("must survive\n", encoding="utf-8")
    real_rename = artifact_module.os.rename
    swapped = False

    def racing_rename(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        if not swapped and source == _stage_id() and src_dir_fd is not None:
            swapped = True
            real_rename(staged.path, moved)
            staged.path.symlink_to(outside, target_is_directory=True)
        real_rename(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(artifact_module.os, "rename", racing_rename)

    with pytest.raises(ArtifactValidationError, match="staged Run root changed"):
        repository.consume_staged_run(
            staging_id=_stage_id(),
            expected_ref=snapshot.ref,
        )

    assert swapped
    assert staged.path.is_symlink()
    assert moved.is_dir()
    assert sentinel.read_text(encoding="utf-8") == "must survive\n"


def test_staged_run_consumption_rebinds_the_verified_inode_before_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    _sealed_run(staging_root)
    snapshot = _import(repository)
    tombstone_name = f".consuming-{_stage_id()}"
    tombstone = staging_root / tombstone_name
    moved = staging_root / "verified-before-removal-race"
    substituted = staging_root / _stage_id("2")
    substituted.mkdir(mode=0o700)
    sentinel = substituted / "sentinel.txt"
    sentinel.write_text("must survive\n", encoding="utf-8")
    real_open = artifact_module.os.open
    swapped = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and path == tombstone_name and dir_fd is not None:
            swapped = True
            tombstone.rename(moved)
            substituted.rename(tombstone)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(artifact_module.os, "open", racing_open)

    with pytest.raises(ArtifactValidationError, match="filesystem entry changed"):
        repository.consume_staged_run(
            staging_id=_stage_id(),
            expected_ref=snapshot.ref,
        )

    assert swapped
    assert moved.is_dir()
    assert (tombstone / sentinel.name).read_text(encoding="utf-8") == "must survive\n"


def test_import_rejects_a_symlinked_staging_run_and_nested_symlink(tmp_path: Path) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    symlinked_id = _stage_id("2")
    (staging_root / symlinked_id).symlink_to(staged.path, target_is_directory=True)

    with pytest.raises(ArtifactValidationError, match="staged Run must be a real directory"):
        _import(repository, staging_id=symlinked_id)

    (staged.path / "nested-link").symlink_to(staged.path / "result.txt")
    with pytest.raises(ArtifactValidationError, match="cannot contain symbolic links"):
        _import(repository)


def test_import_rejects_hard_links_and_special_files(tmp_path: Path) -> None:
    hard_repository, hard_staging, _ = _repository(tmp_path / "hard-link")
    hard_store = _sealed_run(hard_staging)
    os.link(hard_store.path / "result.txt", hard_store.path / "result-copy.txt")
    with pytest.raises(ArtifactValidationError, match="hard-linked"):
        _import(hard_repository)

    special_repository, special_staging, _ = _repository(tmp_path / "special")
    special_store = _sealed_run(special_staging)
    os.mkfifo(special_store.path / "unexpected.fifo")
    with pytest.raises(ArtifactValidationError, match="special files"):
        _import(special_repository)


def test_import_normalizes_overlong_tree_path_as_repository_error(tmp_path: Path) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    current_fd = os.open(staged.path, os.O_RDONLY)
    try:
        for index in range(17):
            component = f"d{index:02d}-" + "x" * 246
            os.mkdir(component, mode=0o700, dir_fd=current_fd)
            child_fd = os.open(component, os.O_RDONLY, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = child_fd
        file_descriptor = os.open(
            "overlong.txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=current_fd,
        )
        os.write(file_descriptor, b"bounded failure\n")
        os.close(file_descriptor)
    finally:
        os.close(current_fd)

    with pytest.raises(ArtifactValidationError, match="entry metadata is invalid"):
        _import(repository)


def test_import_rejects_an_integrity_invalid_run_after_private_copy(tmp_path: Path) -> None:
    repository, staging_root, repository_root = _repository(tmp_path)
    staged = _sealed_run(staging_root)
    (staged.path / "result.txt").write_text("tampered\n", encoding="utf-8")

    with pytest.raises(ArtifactValidationError, match="copied staged Run failed"):
        _import(repository)

    assert list((repository_root / "v1" / "sha256").iterdir()) == []
    assert list((repository_root / "objects").iterdir()) == []
    assert not list(repository_root.glob(".incoming-*"))


def test_streamed_file_count_depth_and_size_bounds_are_enforced(tmp_path: Path) -> None:
    count_repository, count_staging, _ = _repository(
        tmp_path / "count", limits=ArtifactRepositoryLimits(max_files=2)
    )
    _sealed_run(count_staging)
    with pytest.raises(ArtifactValidationError, match="file-count"):
        _import(count_repository)

    entry_repository, entry_staging, _ = _repository(
        tmp_path / "entries",
        limits=ArtifactRepositoryLimits(max_entries=3),
    )
    _sealed_run(entry_staging)
    with pytest.raises(ArtifactValidationError, match="entry-count"):
        _import(entry_repository)

    depth_repository, depth_staging, _ = _repository(
        tmp_path / "depth", limits=ArtifactRepositoryLimits(max_depth=2)
    )
    _sealed_run(depth_staging, result_path="one/two/result.txt")
    with pytest.raises(ArtifactValidationError, match="depth"):
        _import(depth_repository)

    file_repository, file_staging, _ = _repository(
        tmp_path / "file-size",
        limits=ArtifactRepositoryLimits(max_file_bytes=32, max_total_bytes=1_024),
    )
    _sealed_run(file_staging, result="x" * 33)
    with pytest.raises(ArtifactValidationError, match=r"file.*size bound"):
        _import(file_repository)

    total_root = tmp_path / "total-size"
    total_staging = total_root / "staging"
    total_repository_root = total_root / "repository"
    total_staging.mkdir(mode=0o700, parents=True)
    total_repository_root.mkdir(mode=0o700)
    total_store = _sealed_run(total_staging)
    sizes = [path.stat().st_size for path in total_store.path.rglob("*") if path.is_file()]
    total_limit = max(sizes)
    total_repository = ManagedArtifactRepository(
        staging_root=total_staging,
        repository_root=total_repository_root,
        limits=ArtifactRepositoryLimits(
            max_file_bytes=total_limit,
            max_total_bytes=total_limit,
        ),
    )
    with pytest.raises(ArtifactValidationError, match="total-size"):
        _import(total_repository)


def test_directory_replacement_race_is_detected_by_descriptor_relative_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, staging_root, repository_root = _repository(tmp_path)
    staged = _sealed_run(staging_root, result_path="nested/result.txt")
    nested = staged.path / "nested"
    moved = staged.path / "nested-before-race"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "result.txt").write_text("substituted\n", encoding="utf-8")
    real_open = artifact_module.os.open
    swapped = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if (
            not swapped
            and path == "nested"
            and dir_fd is not None
            and flags & getattr(os, "O_DIRECTORY", 0)
        ):
            swapped = True
            nested.rename(moved)
            nested.symlink_to(outside, target_is_directory=True)
        return descriptor

    monkeypatch.setattr(artifact_module.os, "open", racing_open)

    with pytest.raises(ArtifactValidationError, match="filesystem entry changed"):
        _import(repository)

    assert swapped
    assert list((repository_root / "v1" / "sha256").iterdir()) == []


def test_content_address_publish_is_exactly_idempotent_and_no_replace(
    tmp_path: Path,
) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    _sealed_run(staging_root)

    first = _import(repository)
    second = _import(repository)
    assert second == first

    with pytest.raises(ArtifactConflict, match="already bound"):
        _import(repository, producer_run_id=f"run_{'b' * 32}")

    assert repository.resolve(first.ref) == first


@pytest.mark.parametrize("_round", range(10))
def test_concurrent_exact_imports_share_one_atomic_content_address(
    tmp_path: Path,
    _round: int,
) -> None:
    repository, staging_root, repository_root = _repository(tmp_path)
    _sealed_run(staging_root)

    with ThreadPoolExecutor(max_workers=4) as executor:
        snapshots = list(executor.map(lambda _: _import(repository), range(8)))

    assert all(snapshot == snapshots[0] for snapshot in snapshots)
    assert [path.name for path in (repository_root / "v1" / "sha256").iterdir()] == [
        snapshots[0].ref.content_digest
    ]
    assert not list(repository_root.glob(".incoming-*"))


def test_failed_atomic_object_rename_leaves_no_partial_published_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, staging_root, repository_root = _repository(tmp_path)
    _sealed_run(staging_root)
    real_rename = artifact_module.os.rename

    def failing_publish(source: os.PathLike[str], destination: os.PathLike[str]) -> None:
        if Path(source).name.startswith(".incoming-"):
            raise OSError(5, "simulated atomic rename failure")
        real_rename(source, destination)

    monkeypatch.setattr(artifact_module.os, "rename", failing_publish)

    with pytest.raises(artifact_module.ArtifactRepositoryError, match="publish failed"):
        _import(repository)

    assert list((repository_root / "v1" / "sha256").iterdir()) == []
    assert not list((repository_root / "objects").rglob("artifact_*"))
    assert not list(repository_root.glob(".incoming-*"))


def test_resolve_fails_closed_on_manifest_tree_and_root_substitution(tmp_path: Path) -> None:
    manifest_repository, manifest_staging, manifest_root = _repository(tmp_path / "manifest")
    _sealed_run(manifest_staging)
    manifest_snapshot = _import(manifest_repository)
    index_path = manifest_root / manifest_snapshot.storage_key
    index_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ArtifactValidationError, match="manifest is invalid"):
        manifest_repository.resolve(manifest_snapshot.ref)

    tree_repository, tree_staging, _ = _repository(tmp_path / "tree")
    _sealed_run(tree_staging)
    tree_snapshot = _import(tree_repository)
    (tree_snapshot.path / "result.txt").write_text("managed tamper\n", encoding="utf-8")
    with pytest.raises(ArtifactValidationError, match="tree differs"):
        tree_repository.resolve(tree_snapshot.ref)

    root_repository, root_staging, _ = _repository(tmp_path / "root")
    _sealed_run(root_staging)
    root_snapshot = _import(root_repository)
    real_run = root_snapshot.path.parent.parent / "moved-run"
    root_snapshot.path.rename(real_run)
    root_snapshot.path.symlink_to(real_run, target_is_directory=True)
    with pytest.raises(ArtifactValidationError, match="managed Run must be a real directory"):
        root_repository.resolve(root_snapshot.ref)

    link_repository, link_staging, _ = _repository(tmp_path / "manifest-link")
    _sealed_run(link_staging)
    link_snapshot = _import(link_repository)
    object_manifest = link_snapshot.path.parent / "manifest.json"
    os.link(object_manifest, link_snapshot.path.parent.parent / "manifest-alias.json")
    with pytest.raises(ArtifactValidationError, match="cannot be hard-linked"):
        link_repository.resolve(link_snapshot.ref)


def test_resolve_requires_canonical_and_metadata_bound_manifests(tmp_path: Path) -> None:
    repository, staging_root, repository_root = _repository(tmp_path)
    _sealed_run(staging_root)
    snapshot = _import(repository)
    index_path = repository_root / snapshot.storage_key
    object_manifest_path = snapshot.path.parent / "manifest.json"

    manifest = json.loads(index_path.read_bytes())
    noncanonical = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    index_path.write_bytes(noncanonical)
    object_manifest_path.write_bytes(noncanonical)
    with pytest.raises(ArtifactValidationError, match="not canonically encoded"):
        repository.resolve(snapshot.ref)

    manifest["ref"]["created_by"] = "worker:forged"
    forged = (
        json.dumps(
            manifest,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    index_path.write_bytes(forged)
    object_manifest_path.write_bytes(forged)
    forged_ref = snapshot.ref.model_copy(update={"created_by": "worker:forged"})
    with pytest.raises(ArtifactValidationError, match="manifest is invalid"):
        repository.resolve(forged_ref)

    unsupported_ref = snapshot.ref.model_copy(update={"repository_version": 2})
    with pytest.raises(ArtifactValidationError, match="unsupported repository version"):
        repository.resolve(unsupported_ref)


def test_manifest_reader_detects_atomic_leaf_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    _sealed_run(staging_root)
    snapshot = _import(repository)
    real_inspect_final = artifact_module._BoundedRegularFileReader._inspect_final
    replaced = False

    def replacing_inspect(path: Path, *, label: str) -> os.stat_result:
        nonlocal replaced
        if label == "artifact index" and not replaced:
            replaced = True
            replacement = path.with_name(f".{path.name}.replacement")
            replacement.write_bytes(path.read_bytes())
            replacement.replace(path)
        return real_inspect_final(path, label=label)

    monkeypatch.setattr(
        artifact_module._BoundedRegularFileReader,
        "_inspect_final",
        staticmethod(replacing_inspect),
    )

    with pytest.raises(ArtifactValidationError, match="file content changed"):
        repository.resolve(snapshot.ref)
    assert replaced


def test_constructor_rejects_symlinked_or_overlapping_owner_roots(tmp_path: Path) -> None:
    real_staging = tmp_path / "real-staging"
    real_staging.mkdir(mode=0o700)
    linked_staging = tmp_path / "linked-staging"
    linked_staging.symlink_to(real_staging, target_is_directory=True)

    with pytest.raises(ValueError, match="staging root cannot be a symbolic link"):
        ManagedArtifactRepository(
            staging_root=linked_staging,
            repository_root=tmp_path / "repository",
        )

    with pytest.raises(ValueError, match="must be disjoint"):
        ManagedArtifactRepository(
            staging_root=real_staging,
            repository_root=real_staging / "repository",
        )


def test_constructor_creates_every_missing_root_component_privately(
    tmp_path: Path,
) -> None:
    staging_parent = tmp_path / "staging-parent"
    staging_root = staging_parent / "nested" / "staging"
    repository_parent = tmp_path / "repository-parent"
    repository_root = repository_parent / "nested" / "repository"
    previous_umask = os.umask(0)
    try:
        ManagedArtifactRepository(
            staging_root=staging_root,
            repository_root=repository_root,
        )
    finally:
        os.umask(previous_umask)

    for path in (
        staging_parent,
        staging_parent / "nested",
        staging_root,
        repository_parent,
        repository_parent / "nested",
        repository_root,
    ):
        assert path.is_dir()
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner and mode policy")
@pytest.mark.parametrize(
    ("root_name", "unsafe_mode"),
    [
        ("staging", 0o755),
        ("staging", 0o707),
        ("repository", 0o744),
        ("repository", 0o701),
    ],
)
def test_constructor_rejects_group_or_other_owner_root_access(
    tmp_path: Path,
    root_name: str,
    unsafe_mode: int,
) -> None:
    staging_root = tmp_path / "staging"
    repository_root = tmp_path / "repository"
    staging_root.mkdir(mode=0o700)
    repository_root.mkdir(mode=0o700)
    unsafe_root = staging_root if root_name == "staging" else repository_root
    unsafe_root.chmod(unsafe_mode)
    try:
        with pytest.raises(
            ValueError,
            match=rf"{root_name} root cannot grant group or other access",
        ):
            ManagedArtifactRepository(
                staging_root=staging_root,
                repository_root=repository_root,
            )
    finally:
        unsafe_root.chmod(0o700)


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner and mode policy")
@pytest.mark.parametrize(
    ("relative", "label"),
    [
        (("objects",), "repository objects root"),
        (("v1",), "repository version root"),
        (("v1", "sha256"), "repository index root"),
    ],
)
def test_constructor_rejects_preexisting_public_repository_internals(
    tmp_path: Path,
    relative: tuple[str, ...],
    label: str,
) -> None:
    staging_root = tmp_path / "staging"
    repository_root = tmp_path / "repository"
    staging_root.mkdir(mode=0o700)
    repository_root.mkdir(mode=0o700)
    ManagedArtifactRepository(
        staging_root=staging_root,
        repository_root=repository_root,
    )
    unsafe = repository_root.joinpath(*relative)
    unsafe.chmod(0o755)
    try:
        with pytest.raises(ValueError, match=rf"{label} cannot grant group or other access"):
            ManagedArtifactRepository(
                staging_root=staging_root,
                repository_root=repository_root,
            )
    finally:
        unsafe.chmod(0o700)


def test_repository_limits_are_strict_and_coherent() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        ArtifactRepositoryLimits(max_files=True)
    with pytest.raises(ValueError, match="cannot exceed"):
        ArtifactRepositoryLimits(max_file_bytes=2, max_total_bytes=1)
    with pytest.raises(ValueError, match="integer bound"):
        ArtifactRepositoryLimits(max_total_bytes=2_147_483_648)


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory fsync policy")
def test_constructor_fsyncs_every_new_root_ancestor_to_existing_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared_a = tmp_path / "shared-a"
    shared_b = shared_a / "shared-b"
    staging_root = shared_b / "staging"
    repository_root = shared_b / "repository"
    syncs: list[tuple[str, Path]] = []
    real_sync = ManagedArtifactRepository._fsync_directory

    def recording_sync(
        repository: ManagedArtifactRepository,
        path: Path,
        *,
        label: str,
    ) -> None:
        syncs.append((label, path.resolve()))
        real_sync(repository, path, label=label)

    monkeypatch.setattr(ManagedArtifactRepository, "_fsync_directory", recording_sync)

    ManagedArtifactRepository(
        staging_root=staging_root,
        repository_root=repository_root,
    )

    assert [path for label, path in syncs if label == "repository root ancestry"] == [
        repository_root.resolve(),
        shared_b.resolve(),
    ]
    assert [path for label, path in syncs if label == "staging root ancestry"] == [
        staging_root.resolve(),
        shared_b.resolve(),
        shared_a.resolve(),
        tmp_path.resolve(),
    ]


def test_import_returns_only_after_object_and_index_directories_are_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, staging_root, _ = _repository(tmp_path)
    _sealed_run(staging_root)
    sync_labels: list[str] = []
    real_sync = repository._fsync_directory

    def recording_sync(path: Path, *, label: str) -> None:
        sync_labels.append(label)
        real_sync(path, label=label)

    monkeypatch.setattr(repository, "_fsync_directory", recording_sync)

    _import(repository)

    assert sync_labels[-1] == "artifact index publish parent"
    assert sync_labels.index("published artifact object") < sync_labels.index(
        "artifact object publish parent"
    )
    assert sync_labels.index("artifact object publish parent") < sync_labels.index(
        "artifact index publish parent"
    )
    assert sync_labels.index("artifact temporary parent") < sync_labels.index(
        "artifact index publish parent"
    )


def test_index_directory_fsync_failure_fails_admission_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, staging_root, repository_root = _repository(tmp_path)
    _sealed_run(staging_root)
    real_sync = repository._fsync_directory

    def failing_final_sync(path: Path, *, label: str) -> None:
        if label == "artifact index publish parent":
            raise ArtifactRepositoryError("simulated index directory durability failure")
        real_sync(path, label=label)

    monkeypatch.setattr(repository, "_fsync_directory", failing_final_sync)

    with pytest.raises(ArtifactRepositoryError, match=r"simulated.*durability failure"):
        _import(repository)

    # The atomic link may be visible, but the caller receives no admitted ref
    # until a subsequent attempt durably syncs that directory entry.
    assert len(list((repository_root / "v1" / "sha256").iterdir())) == 1
    monkeypatch.setattr(repository, "_fsync_directory", real_sync)
    snapshot = _import(repository)
    assert repository.resolve(snapshot.ref) == snapshot


def test_import_fails_closed_without_directory_fsync_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, staging_root, repository_root = _repository(tmp_path)
    _sealed_run(staging_root)
    monkeypatch.setattr(artifact_module, "_DIRECTORY_FSYNC_SUPPORTED", False)

    with pytest.raises(ArtifactRepositoryError, match="requires POSIX directory fsync"):
        _import(repository)

    assert list((repository_root / "v1" / "sha256").iterdir()) == []
    assert not list(repository_root.glob(".incoming-*"))
