"""Bounded immutable filesystem storage for sealed Control Plane Run artifacts."""

from __future__ import annotations

import errno
import json
import os
import shutil
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from tempfile import mkdtemp
from typing import Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.control_plane.models import ArtifactRef
from pajin.runtime.store import RunIntegrityError, verify_run_integrity

_STAGING_ID_PATTERN = r"^stage_[0-9a-f]{32}$"
_STAGING_ID_LENGTH = len("stage_") + 32
_HASH_PATTERN = r"^[a-f0-9]{64}$"
_REPOSITORY_VERSION = 1
_COPY_CHUNK_BYTES = 1024 * 1024
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_DIRECTORY_FSYNC_SUPPORTED = os.name == "posix" and hasattr(os, "O_DIRECTORY")


class ArtifactRepositoryError(RuntimeError):
    """Base class for managed artifact repository failures."""


class ArtifactValidationError(ArtifactRepositoryError):
    """The staged or managed object violates the repository contract."""


class ArtifactNotFound(ArtifactRepositoryError):
    """The exact immutable artifact version is absent."""


class ArtifactConflict(ArtifactRepositoryError):
    """A content address is already bound to different immutable metadata."""


@dataclass(frozen=True)
class ArtifactRepositoryLimits:
    """Stream-enforced bounds for one imported sealed Run tree."""

    max_file_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_files: int = 10_000
    max_entries: int = 20_000
    max_depth: int = 32

    def __post_init__(self) -> None:
        values = {
            "max_file_bytes": self.max_file_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_files": self.max_files,
            "max_entries": self.max_entries,
            "max_depth": self.max_depth,
        }
        for name, value in values.items():
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("max_file_bytes cannot exceed max_total_bytes")
        if self.max_total_bytes > 2_147_483_647:
            raise ValueError("max_total_bytes exceeds the ArtifactRef integer bound")


@dataclass(frozen=True)
class ManagedArtifactSnapshot:
    """Trusted internal handle to one freshly verified managed Run."""

    ref: ArtifactRef
    storage_key: str
    path: Path


class _TreeEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=4_096)
    size: int = Field(strict=True, ge=0, le=2_147_483_647)
    sha256: str = Field(pattern=_HASH_PATTERN)

    @field_validator("path")
    @classmethod
    def require_canonical_relative_path(cls, value: str) -> str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("artifact paths must be valid UTF-8") from exc
        path = PurePosixPath(value)
        if path.is_absolute() or value != path.as_posix() or ".." in path.parts:
            raise ValueError("artifact paths must be canonical and relative")
        if any(part in {"", "."} for part in path.parts):
            raise ValueError("artifact paths cannot contain empty or dot segments")
        return value


class _ArtifactManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: int = Field(default=1, strict=True)
    storage_key: str = Field(pattern=r"^v1/sha256/[a-f0-9]{64}$")
    object_key: str = Field(pattern=r"^objects/[a-f0-9]{64}/artifact_[a-f0-9]{32}$")
    ref: ArtifactRef
    tree: tuple[_TreeEntry, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def require_canonical_bindings(self) -> Self:
        if self.format_version != 1:
            raise ValueError("unsupported artifact manifest version")
        if tuple(sorted(self.tree, key=lambda item: item.path)) != self.tree:
            raise ValueError("artifact manifest tree is not canonically ordered")
        paths = [item.path for item in self.tree]
        if len(paths) != len(set(paths)):
            raise ValueError("artifact manifest tree contains duplicate paths")
        digest = self.ref.content_digest
        if self.storage_key != f"v1/sha256/{digest}":
            raise ValueError("artifact storage key does not match its content digest")
        if self.object_key != f"objects/{digest}/{self.ref.artifact_id}":
            raise ValueError("artifact object key does not match its immutable identity")
        return self


@dataclass(frozen=True)
class _ScannedTree:
    entries: tuple[_TreeEntry, ...]
    byte_length: int

    @property
    def digest(self) -> str:
        material = [entry.model_dump(mode="json") for entry in self.entries]
        encoded = json.dumps(
            material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return sha256(encoded).hexdigest()


class ManagedArtifactRepository:
    """Import and freshly resolve sealed Runs under owner-selected filesystem roots.

    Callers provide only an opaque staging identifier. Raw Worker paths never cross
    this boundary. A content-address index is published with a hard-link create,
    which is atomic and cannot replace an existing address. Durable publication
    currently requires POSIX directory ``fsync`` support; import fails closed on
    platforms that cannot provide it.
    """

    def __init__(
        self,
        *,
        staging_root: Path,
        repository_root: Path,
        limits: ArtifactRepositoryLimits | None = None,
    ) -> None:
        self.limits = limits or ArtifactRepositoryLimits()
        self.staging_root, staging_creation_chain = self._prepare_owner_root(
            staging_root,
            label="staging",
        )
        self.repository_root, repository_creation_chain = self._prepare_owner_root(
            repository_root,
            label="repository",
        )
        if (
            self.staging_root == self.repository_root
            or self.staging_root in self.repository_root.parents
            or self.repository_root in self.staging_root.parents
        ):
            raise ValueError("staging and repository roots must be disjoint")
        self._require_private_owner_directory(
            self.repository_root,
            label="repository root",
            configuration=True,
        )
        self._require_private_owner_directory(
            self.staging_root,
            label="staging root",
            configuration=True,
        )
        self._objects_root = self.repository_root / "objects"
        self._version_root = self.repository_root / "v1"
        self._indexes_root = self._version_root / "sha256"
        self._objects_root.mkdir(mode=0o700, exist_ok=True)
        self._version_root.mkdir(mode=0o700, exist_ok=True)
        self._indexes_root.mkdir(mode=0o700, exist_ok=True)
        self._require_directory(self._objects_root, label="repository objects root")
        self._require_directory(self._version_root, label="repository version root")
        self._require_directory(self._indexes_root, label="repository index root")
        self._require_private_owner_directory(
            self._objects_root,
            label="repository objects root",
            configuration=True,
        )
        self._require_private_owner_directory(
            self._version_root,
            label="repository version root",
            configuration=True,
        )
        self._require_private_owner_directory(
            self._indexes_root,
            label="repository index root",
            configuration=True,
        )
        if _DIRECTORY_FSYNC_SUPPORTED:
            self._fsync_directory(self._objects_root, label="repository objects root")
            self._fsync_directory(self._indexes_root, label="repository index root")
            self._fsync_directory(self._version_root, label="repository version root")
            self._fsync_directory(self.repository_root, label="repository root")
            self._fsync_creation_chain(
                repository_creation_chain,
                label="repository root ancestry",
            )
            self._fsync_creation_chain(
                staging_creation_chain,
                label="staging root ancestry",
            )

    def import_run(
        self,
        *,
        staging_id: str,
        producer_run_id: str,
        media_type: str,
        schema_kind: str,
        created_by: str,
    ) -> ManagedArtifactSnapshot:
        """Copy, verify, and atomically publish one staged sealed Run."""

        if not _DIRECTORY_FSYNC_SUPPORTED:
            raise ArtifactRepositoryError(
                "durable artifact import requires POSIX directory fsync support"
            )
        self._require_repository_layout()
        self._require_directory(self.staging_root, label="staging root")
        self._require_private_owner_directory(self.staging_root, label="staging root")
        self._validate_staging_id(staging_id)
        staged_run = self.staging_root / staging_id
        self._require_directory(staged_run, label="staged Run")

        private_root = Path(mkdtemp(prefix=".incoming-", dir=self.repository_root))
        copied_run = private_root / "run"
        copied_run.mkdir(mode=0o700)
        published = False
        try:
            copied_tree = self._scan_tree(staged_run, copy_to=copied_run)
            try:
                verification = verify_run_integrity(copied_run)
            except (IndexError, OSError, RunIntegrityError, ValueError) as exc:
                raise ArtifactValidationError(
                    "copied staged Run failed integrity verification"
                ) from exc

            # Reopen the private copy so the digest binds the exact verified tree,
            # including the event and integrity logs themselves.
            verified_tree = self._scan_tree(copied_run)
            if verified_tree != copied_tree:
                raise ArtifactValidationError("copied Run changed during integrity verification")
            content_digest = verified_tree.digest
            artifact_id = self._artifact_id(
                producer_run_id=producer_run_id,
                run_id=verification.run_id,
                media_type=media_type,
                schema_kind=schema_kind,
                byte_length=verified_tree.byte_length,
                content_digest=content_digest,
                integrity_root_digest=verification.root_digest,
                created_by=created_by,
            )
            try:
                ref = ArtifactRef(
                    artifact_id=artifact_id,
                    repository_version=_REPOSITORY_VERSION,
                    media_type=media_type,
                    schema_kind=schema_kind,
                    byte_length=verified_tree.byte_length,
                    content_digest=content_digest,
                    producer_run_id=producer_run_id,
                    run_id=verification.run_id,
                    integrity_root_digest=verification.root_digest,
                    created_by=created_by,
                )
            except ValidationError as exc:
                raise ArtifactValidationError("artifact metadata is invalid") from exc

            storage_key = self._storage_key(content_digest)
            object_key = self._object_key(ref)
            manifest = _ArtifactManifest(
                storage_key=storage_key,
                object_key=object_key,
                ref=ref,
                tree=verified_tree.entries,
            )
            manifest_bytes = self._manifest_bytes(manifest)
            if len(manifest_bytes) > _MAX_MANIFEST_BYTES:
                raise ArtifactValidationError("artifact manifest exceeds the size bound")
            self._write_exclusive(private_root / "manifest.json", manifest_bytes)
            self._fsync_directory(private_root, label="private artifact object")

            object_path = self.repository_root / object_key
            object_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._require_directory(object_path.parent, label="artifact object parent")
            self._require_private_owner_directory(
                object_path.parent, label="artifact object parent"
            )
            if self._lexists(object_path):
                self._require_existing_object(object_path, manifest_bytes)
            else:
                try:
                    os.rename(private_root, object_path)
                    published = True
                except OSError as exc:
                    if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                        raise ArtifactRepositoryError("artifact object publish failed") from exc
                    self._require_existing_object(object_path, manifest_bytes)

            # Persist both sides of the rename and every newly introduced parent
            # entry before the content address can become admission authority.
            self._fsync_directory(object_path, label="published artifact object")
            self._fsync_directory(object_path.parent, label="artifact object publish parent")
            self._fsync_directory(self._objects_root, label="repository objects root")
            self._fsync_directory(self.repository_root, label="artifact temporary parent")

            index_path = self.repository_root / storage_key
            self._publish_index_no_replace(index_path, manifest_bytes)
            return self.resolve(ref)
        finally:
            if not published and self._lexists(private_root):
                shutil.rmtree(private_root)

    def resolve(self, ref: ArtifactRef) -> ManagedArtifactSnapshot:
        """Freshly verify the manifest, complete tree, Run chain, and root digest."""

        self._require_repository_layout()
        if not isinstance(ref, ArtifactRef):
            raise ArtifactValidationError("resolve requires an ArtifactRef")
        storage_key = self._storage_key(ref.content_digest)
        index_path = self.repository_root / storage_key
        if not self._lexists(index_path):
            raise ArtifactNotFound(
                f"artifact {ref.artifact_id} repository version {ref.repository_version} not found"
            )
        index_bytes = self._read_regular_file(index_path, label="artifact index")
        manifest = self._parse_manifest(index_bytes)
        if manifest.ref != ref:
            raise ArtifactConflict("artifact reference differs from the content-address manifest")
        if manifest.storage_key != storage_key:
            raise ArtifactValidationError("artifact index is stored at the wrong content address")

        object_path = self.repository_root / manifest.object_key
        self._require_directory(object_path, label="artifact object")
        self._require_private_owner_directory(object_path, label="artifact object")
        self._require_exact_object_layout(object_path)
        object_manifest_bytes = self._read_regular_file(
            object_path / "manifest.json",
            label="artifact object manifest",
            require_single_link=True,
        )
        if object_manifest_bytes != index_bytes:
            raise ArtifactValidationError("artifact index and object manifest differ")

        run_path = object_path / "run"
        self._require_directory(run_path, label="managed Run")
        self._require_private_owner_directory(run_path, label="managed Run")
        observed_tree = self._scan_tree(run_path)
        if observed_tree.entries != manifest.tree:
            raise ArtifactValidationError("managed Run tree differs from its manifest")
        if observed_tree.byte_length != ref.byte_length:
            raise ArtifactValidationError("managed Run byte length differs from its reference")
        if observed_tree.digest != ref.content_digest:
            raise ArtifactValidationError("managed Run content digest differs from its reference")
        try:
            verification = verify_run_integrity(run_path)
        except (IndexError, OSError, RunIntegrityError, ValueError) as exc:
            raise ArtifactValidationError("managed Run integrity verification failed") from exc
        if verification.run_id != ref.run_id:
            raise ArtifactValidationError("managed Run identifier differs from its reference")
        if verification.root_digest != ref.integrity_root_digest:
            raise ArtifactValidationError("managed Run root digest differs from its reference")
        if self._read_regular_file(index_path, label="artifact index") != index_bytes:
            raise ArtifactValidationError("artifact manifest changed during resolution")
        return ManagedArtifactSnapshot(ref=ref, storage_key=storage_key, path=run_path)

    def _scan_tree(self, root: Path, *, copy_to: Path | None = None) -> _ScannedTree:
        self._require_directory(root, label="Run tree root")
        if copy_to is not None:
            self._require_directory(copy_to, label="private copy root")
        entries: list[_TreeEntry] = []
        total_bytes = 0
        entry_count = 0
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW

        try:
            root_before = root.lstat()
            source_root_fd = os.open(root, directory_flags)
        except OSError as exc:
            raise ArtifactValidationError("Run tree root cannot be opened safely") from exc
        destination_root_fd: int | None = None
        try:
            root_opened = os.fstat(source_root_fd)
            self._require_same_entry(root_before, root_opened)
            if not stat.S_ISDIR(root_opened.st_mode):
                raise ArtifactValidationError("Run tree root must remain a directory")
            if copy_to is not None:
                destination_root_fd = os.open(copy_to, directory_flags)

            def walk(
                source_fd: int,
                destination_fd: int | None,
                relative_parts: tuple[str, ...],
            ) -> None:
                nonlocal entry_count, total_bytes
                try:
                    with os.scandir(source_fd) as iterator:
                        for entry in iterator:
                            visit_entry(
                                source_fd,
                                destination_fd,
                                relative_parts,
                                entry.name,
                            )
                    if destination_fd is not None:
                        self._fsync_directory_descriptor(
                            destination_fd,
                            label="copied Run directory",
                        )
                except OSError as exc:
                    raise ArtifactValidationError("Run tree cannot be enumerated") from exc

            def visit_entry(
                source_fd: int,
                destination_fd: int | None,
                relative_parts: tuple[str, ...],
                name: str,
            ) -> None:
                nonlocal entry_count, total_bytes
                try:
                    entry_count += 1
                    if entry_count > self.limits.max_entries:
                        raise ArtifactValidationError(
                            "Run tree exceeds the configured entry-count bound"
                        )
                    relative = (*relative_parts, name)
                    if len(relative) > self.limits.max_depth:
                        raise ArtifactValidationError("Run tree exceeds the configured depth bound")
                    relative_path = PurePosixPath(*relative).as_posix()
                    try:
                        relative_path.encode("utf-8")
                        observed = os.stat(
                            name,
                            dir_fd=source_fd,
                            follow_symlinks=False,
                        )
                    except (OSError, UnicodeEncodeError) as exc:
                        raise ArtifactValidationError("Run tree entry cannot be inspected") from exc
                    mode = observed.st_mode
                    if stat.S_ISLNK(mode):
                        raise ArtifactValidationError("Run trees cannot contain symbolic links")
                    if stat.S_ISDIR(mode):
                        try:
                            child_source_fd = os.open(
                                name,
                                directory_flags,
                                dir_fd=source_fd,
                            )
                        except OSError as exc:
                            raise ArtifactValidationError(
                                "Run directory cannot be opened safely"
                            ) from exc
                        child_destination_fd: int | None = None
                        try:
                            opened = os.fstat(child_source_fd)
                            self._require_same_entry(observed, opened)
                            if destination_fd is not None:
                                os.mkdir(name, mode=0o700, dir_fd=destination_fd)
                                child_destination_fd = os.open(
                                    name,
                                    directory_flags,
                                    dir_fd=destination_fd,
                                )
                            walk(child_source_fd, child_destination_fd, relative)
                            final = os.fstat(child_source_fd)
                            self._require_same_entry(opened, final)
                            current = os.stat(
                                name,
                                dir_fd=source_fd,
                                follow_symlinks=False,
                            )
                            self._require_same_entry(final, current)
                        except OSError as exc:
                            raise ArtifactValidationError(
                                "Run directory changed while being copied"
                            ) from exc
                        finally:
                            if child_destination_fd is not None:
                                os.close(child_destination_fd)
                            os.close(child_source_fd)
                        return
                    if not stat.S_ISREG(mode):
                        raise ArtifactValidationError("Run trees cannot contain special files")
                    if observed.st_nlink != 1:
                        raise ArtifactValidationError("Run trees cannot contain hard-linked files")
                    if len(entries) >= self.limits.max_files:
                        raise ArtifactValidationError(
                            "Run tree exceeds the configured file-count bound"
                        )
                    if observed.st_size > self.limits.max_file_bytes:
                        raise ArtifactValidationError("Run file exceeds the configured size bound")
                    digest, size = self._stream_file(
                        source_fd,
                        name,
                        destination_fd,
                        initial_stat=observed,
                        total_before=total_bytes,
                    )
                    total_bytes += size
                    entries.append(_TreeEntry(path=relative_path, size=size, sha256=digest))
                except OSError as exc:
                    raise ArtifactValidationError(
                        "Run tree entry changed while being scanned"
                    ) from exc

            walk(source_root_fd, destination_root_fd, ())
            root_final = os.fstat(source_root_fd)
            self._require_same_entry(root_opened, root_final)
            try:
                root_current = root.lstat()
            except OSError as exc:
                raise ArtifactValidationError("Run tree root disappeared during scan") from exc
            self._require_same_entry(root_final, root_current)
        finally:
            if destination_root_fd is not None:
                os.close(destination_root_fd)
            os.close(source_root_fd)
        ordered = tuple(sorted(entries, key=lambda item: item.path))
        if not ordered:
            raise ArtifactValidationError("Run tree must contain at least one regular file")
        return _ScannedTree(entries=ordered, byte_length=total_bytes)

    def _stream_file(
        self,
        source_directory_fd: int,
        name: str,
        destination_directory_fd: int | None,
        *,
        initial_stat: os.stat_result,
        total_before: int,
    ) -> tuple[str, int]:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            source_fd = os.open(name, flags, dir_fd=source_directory_fd)
        except OSError as exc:
            raise ArtifactValidationError("Run file cannot be opened safely") from exc
        destination_fd: int | None = None
        try:
            opened_stat = os.fstat(source_fd)
            self._require_same_entry(initial_stat, opened_stat)
            if not stat.S_ISREG(opened_stat.st_mode) or opened_stat.st_nlink != 1:
                raise ArtifactValidationError("Run file changed type or link count during import")
            if destination_directory_fd is not None:
                destination_fd = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=destination_directory_fd,
                )
            digest = sha256()
            size = 0
            while True:
                chunk = os.read(source_fd, _COPY_CHUNK_BYTES)
                if not chunk:
                    break
                size += len(chunk)
                if size > self.limits.max_file_bytes:
                    raise ArtifactValidationError("Run file exceeds the configured size bound")
                if total_before + size > self.limits.max_total_bytes:
                    raise ArtifactValidationError(
                        "Run tree exceeds the configured total-size bound"
                    )
                digest.update(chunk)
                if destination_fd is not None:
                    self._write_all(destination_fd, chunk)
            final_stat = os.fstat(source_fd)
            self._require_same_entry(opened_stat, final_stat)
            if size != final_stat.st_size:
                raise ArtifactValidationError("Run file changed length while being read")
            try:
                path_stat = os.stat(
                    name,
                    dir_fd=source_directory_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise ArtifactValidationError("Run file disappeared while being read") from exc
            self._require_same_entry(final_stat, path_stat)
            if destination_fd is not None:
                os.fsync(destination_fd)
            return digest.hexdigest(), size
        finally:
            if destination_fd is not None:
                os.close(destination_fd)
            os.close(source_fd)

    @staticmethod
    def _require_same_entry(before: os.stat_result, after: os.stat_result) -> None:
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_nlink,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
        )
        if before_identity != after_identity:
            raise ArtifactValidationError("filesystem entry changed while being read")

    @staticmethod
    def _require_same_inode(before: os.stat_result, after: os.stat_result) -> None:
        """Bind a durability handle without rejecting legitimate sibling writes."""

        before_identity = (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode))
        after_identity = (after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode))
        if before_identity != after_identity:
            raise ArtifactValidationError("filesystem directory was substituted")

    @staticmethod
    def _require_same_file_content(before: os.stat_result, after: os.stat_result) -> None:
        """Allow atomic-index link-count churn while binding bytes to one inode."""

        before_identity = (
            before.st_dev,
            before.st_ino,
            stat.S_IFMT(before.st_mode),
            before.st_size,
            before.st_mtime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            stat.S_IFMT(after.st_mode),
            after.st_size,
            after.st_mtime_ns,
        )
        if before_identity != after_identity:
            raise ArtifactValidationError("filesystem file content changed while being read")

    @staticmethod
    def _write_all(file_descriptor: int, content: bytes) -> None:
        offset = 0
        while offset < len(content):
            offset += os.write(file_descriptor, content[offset:])

    @staticmethod
    def _artifact_id(
        *,
        producer_run_id: str,
        run_id: str,
        media_type: str,
        schema_kind: str,
        byte_length: int,
        content_digest: str,
        integrity_root_digest: str,
        created_by: str,
    ) -> str:
        material = {
            "byteLength": byte_length,
            "contentDigest": content_digest,
            "createdBy": created_by,
            "integrityRootDigest": integrity_root_digest,
            "mediaType": media_type,
            "producerRunId": producer_run_id,
            "repositoryVersion": _REPOSITORY_VERSION,
            "runId": run_id,
            "schemaKind": schema_kind,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"artifact_{sha256(encoded).hexdigest()[:32]}"

    @staticmethod
    def _storage_key(content_digest: str) -> str:
        return f"v1/sha256/{content_digest}"

    @staticmethod
    def _object_key(ref: ArtifactRef) -> str:
        return f"objects/{ref.content_digest}/{ref.artifact_id}"

    @staticmethod
    def _manifest_bytes(manifest: _ArtifactManifest) -> bytes:
        return (
            json.dumps(
                manifest.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )

    def _publish_index_no_replace(self, index_path: Path, content: bytes) -> None:
        index_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._require_directory(index_path.parent, label="artifact index parent")
        self._require_private_owner_directory(index_path.parent, label="artifact index parent")
        temporary_index = index_path.parent / f".{index_path.name}.{uuid4().hex}.tmp"
        self._write_exclusive(temporary_index, content)
        try:
            try:
                os.link(temporary_index, index_path, follow_symlinks=False)
            except FileExistsError:
                existing = self._read_regular_file(index_path, label="artifact index")
                if existing != content:
                    raise ArtifactConflict(
                        "content address is already bound to different artifact metadata"
                    ) from None
        finally:
            try:
                temporary_index.unlink(missing_ok=True)
            finally:
                # The durable authority point is this parent-directory fsync:
                # admission must not proceed merely because the link is visible
                # in volatile page cache state.
                self._fsync_directory(
                    index_path.parent,
                    label="artifact index publish parent",
                )

    def _require_existing_object(self, object_path: Path, expected_manifest: bytes) -> None:
        self._require_directory(object_path, label="existing artifact object")
        self._require_private_owner_directory(object_path, label="existing artifact object")
        self._require_exact_object_layout(object_path)
        actual = self._read_regular_file(
            object_path / "manifest.json",
            label="existing artifact object manifest",
            require_single_link=True,
        )
        if actual != expected_manifest:
            raise ArtifactConflict("artifact identity is already bound to different metadata")

    @staticmethod
    def _require_exact_object_layout(object_path: Path) -> None:
        try:
            names = {entry.name for entry in os.scandir(object_path)}
        except OSError as exc:
            raise ArtifactValidationError("artifact object cannot be enumerated") from exc
        if names != {"manifest.json", "run"}:
            raise ArtifactValidationError("artifact object layout is not canonical")

    def _read_regular_file(
        self,
        path: Path,
        *,
        label: str,
        require_single_link: bool = False,
    ) -> bytes:
        try:
            observed = path.lstat()
        except FileNotFoundError as exc:
            raise ArtifactNotFound(f"{label} is missing") from exc
        except OSError as exc:
            raise ArtifactValidationError(f"{label} cannot be inspected") from exc
        if not stat.S_ISREG(observed.st_mode):
            raise ArtifactValidationError(f"{label} must be a regular file")
        if require_single_link and observed.st_nlink != 1:
            raise ArtifactValidationError(f"{label} cannot be hard-linked")
        if observed.st_size > _MAX_MANIFEST_BYTES:
            raise ArtifactValidationError(f"{label} exceeds the manifest size bound")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ArtifactValidationError(f"{label} cannot be opened safely") from exc
        try:
            opened = os.fstat(descriptor)
            require_stable = (
                self._require_same_entry if require_single_link else self._require_same_file_content
            )
            require_stable(observed, opened)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(descriptor, _COPY_CHUNK_BYTES)
                if not chunk:
                    break
                size += len(chunk)
                if size > _MAX_MANIFEST_BYTES:
                    raise ArtifactValidationError(f"{label} exceeds the manifest size bound")
                chunks.append(chunk)
            final = os.fstat(descriptor)
            require_stable(opened, final)
            if size != final.st_size:
                raise ArtifactValidationError(f"{label} changed while being read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    @staticmethod
    def _parse_manifest(content: bytes) -> _ArtifactManifest:
        try:
            return _ArtifactManifest.model_validate_json(content)
        except (ValidationError, ValueError) as exc:
            raise ArtifactValidationError("artifact manifest is invalid") from exc

    @staticmethod
    def _write_exclusive(path: Path, content: bytes) -> None:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            raise ArtifactRepositoryError("private artifact metadata creation failed") from exc
        try:
            try:
                ManagedArtifactRepository._write_all(descriptor, content)
                os.fsync(descriptor)
            except OSError as exc:
                raise ArtifactRepositoryError(
                    "private artifact metadata durability sync failed"
                ) from exc
        finally:
            os.close(descriptor)

    @staticmethod
    def _fsync_directory_descriptor(file_descriptor: int, *, label: str) -> None:
        if not _DIRECTORY_FSYNC_SUPPORTED:
            raise ArtifactRepositoryError(
                "durable artifact import requires POSIX directory fsync support"
            )
        try:
            os.fsync(file_descriptor)
        except OSError as exc:
            raise ArtifactRepositoryError(f"{label} durability sync failed") from exc

    def _fsync_directory(self, path: Path, *, label: str) -> None:
        if not _DIRECTORY_FSYNC_SUPPORTED:
            raise ArtifactRepositoryError(
                "durable artifact import requires POSIX directory fsync support"
            )
        flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            before = path.lstat()
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ArtifactRepositoryError(f"{label} cannot be opened for durability") from exc
        try:
            opened = os.fstat(descriptor)
            self._require_same_inode(before, opened)
            if not stat.S_ISDIR(opened.st_mode):
                raise ArtifactRepositoryError(f"{label} must remain a directory")
            self._fsync_directory_descriptor(descriptor, label=label)
            try:
                current = path.lstat()
            except OSError as exc:
                raise ArtifactRepositoryError(
                    f"{label} disappeared during durability sync"
                ) from exc
            self._require_same_inode(opened, current)
        finally:
            os.close(descriptor)

    def _fsync_creation_chain(self, paths: tuple[Path, ...], *, label: str) -> None:
        """Persist every newly created root ancestor through its existing anchor."""

        seen: set[Path] = set()
        for path in paths:
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            self._fsync_directory(resolved, label=label)

    @staticmethod
    def _prepare_owner_root(path: Path, *, label: str) -> tuple[Path, tuple[Path, ...]]:
        raw = Path(path).expanduser().absolute()
        if raw.is_symlink():
            raise ValueError(f"{label} root cannot be a symbolic link")
        creation_chain: list[Path] = []
        cursor = raw
        while not os.path.lexists(cursor):
            creation_chain.append(cursor)
            parent = cursor.parent
            if parent == cursor:
                raise ValueError(f"{label} root has no existing filesystem anchor")
            cursor = parent
        if creation_chain:
            creation_chain.append(cursor)
        raw.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            observed = raw.lstat()
        except OSError as exc:
            raise ValueError(f"{label} root cannot be inspected") from exc
        if not stat.S_ISDIR(observed.st_mode):
            raise ValueError(f"{label} root must be a directory")
        return raw.resolve(), tuple(creation_chain)

    @staticmethod
    def _require_directory(path: Path, *, label: str) -> None:
        try:
            observed = path.lstat()
        except FileNotFoundError as exc:
            raise ArtifactNotFound(f"{label} is missing") from exc
        except OSError as exc:
            raise ArtifactValidationError(f"{label} cannot be inspected") from exc
        if not stat.S_ISDIR(observed.st_mode):
            raise ArtifactValidationError(f"{label} must be a real directory")

    @staticmethod
    def _require_private_owner_directory(
        path: Path,
        *,
        label: str,
        configuration: bool = False,
    ) -> None:
        error_type: type[ValueError] | type[ArtifactValidationError]
        error_type = ValueError if configuration else ArtifactValidationError
        try:
            observed = path.lstat()
        except OSError as exc:
            raise error_type(f"{label} cannot be inspected") from exc
        if not stat.S_ISDIR(observed.st_mode):
            raise error_type(f"{label} must be a directory")
        if os.name == "posix" and hasattr(os, "geteuid"):
            if observed.st_uid != os.geteuid():
                raise error_type(f"{label} must be owned by the current process user")
            if observed.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise error_type(f"{label} cannot grant group or other access")

    def _require_repository_layout(self) -> None:
        for path, label in (
            (self.repository_root, "repository root"),
            (self._objects_root, "repository objects root"),
            (self._version_root, "repository version root"),
            (self._indexes_root, "repository index root"),
        ):
            self._require_directory(path, label=label)
            self._require_private_owner_directory(path, label=label)

    @staticmethod
    def _validate_staging_id(staging_id: str) -> None:
        if (
            type(staging_id) is not str
            or len(staging_id) != _STAGING_ID_LENGTH
            or not staging_id.startswith("stage_")
            or any(character not in "0123456789abcdef" for character in staging_id[6:])
        ):
            raise ArtifactValidationError(f"staging_id must match {_STAGING_ID_PATTERN}")

    @staticmethod
    def _lexists(path: Path) -> bool:
        return os.path.lexists(path)
