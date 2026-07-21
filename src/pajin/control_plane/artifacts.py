"""Bounded immutable filesystem storage for sealed Control Plane Run artifacts."""

from __future__ import annotations

import errno
import json
import os
import shutil
import stat
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from tempfile import mkdtemp
from typing import Self
from uuid import uuid4

if sys.platform != "win32":
    import fcntl

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
_TRANSIENT_RUN_LOCK_NAME = ".pajin-run.lock"
_CONSUMING_STAGING_PREFIX = ".consuming-"


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


def _computed_artifact_id(
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
        if self.format_version != _REPOSITORY_VERSION:
            raise ValueError("unsupported artifact manifest version")
        if self.ref.repository_version != _REPOSITORY_VERSION:
            raise ValueError("artifact reference uses an unsupported repository version")
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
        expected_artifact_id = _computed_artifact_id(
            producer_run_id=self.ref.producer_run_id,
            run_id=self.ref.run_id,
            media_type=self.ref.media_type,
            schema_kind=self.ref.schema_kind,
            byte_length=self.ref.byte_length,
            content_digest=self.ref.content_digest,
            integrity_root_digest=self.ref.integrity_root_digest,
            created_by=self.ref.created_by,
        )
        if self.ref.artifact_id != expected_artifact_id:
            raise ValueError("artifact identifier does not bind its immutable metadata")
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


def _require_same_inode(before: os.stat_result, after: os.stat_result) -> None:
    before_identity = (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode))
    after_identity = (after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode))
    if before_identity != after_identity:
        raise ArtifactValidationError("filesystem directory was substituted")


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _create_private_directory(path: Path, *, label: str) -> None:
    """Create and rebind one root component within the available platform boundary."""

    try:
        path.mkdir(mode=0o700, exist_ok=False)
        observed = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} root ancestry cannot be created safely") from exc
    if os.name != "posix":
        try:
            current = path.lstat()
            if _is_link_or_junction(path) or not stat.S_ISDIR(current.st_mode):
                raise ValueError(f"{label} root ancestry must remain a real directory")
            _require_same_inode(observed, current)
        except (OSError, ArtifactValidationError) as exc:
            raise ValueError(f"{label} root ancestry cannot be secured") from exc
        return
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} root ancestry cannot be created safely") from exc
    try:
        opened = os.fstat(descriptor)
        _require_same_inode(observed, opened)
        if not stat.S_ISDIR(opened.st_mode):
            raise ValueError(f"{label} root ancestry must remain a directory")
        fchmod = getattr(os, "fchmod", None)
        if fchmod is None:
            raise ValueError(f"{label} root ancestry cannot enforce private ownership")
        fchmod(descriptor, 0o700)
        final = os.fstat(descriptor)
        _require_same_inode(opened, final)
        if hasattr(os, "geteuid") and final.st_uid != os.geteuid():
            raise ValueError(f"{label} root ancestry must be owned by the current process user")
        current = path.lstat()
        _require_same_inode(final, current)
    except (OSError, ArtifactValidationError) as exc:
        raise ValueError(f"{label} root ancestry cannot be secured") from exc
    finally:
        os.close(descriptor)


def _write_all(file_descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(file_descriptor, content[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "filesystem write made no forward progress")
        offset += written


def _fsync_open_directory(file_descriptor: int, *, label: str) -> None:
    if not _DIRECTORY_FSYNC_SUPPORTED:
        raise ArtifactRepositoryError(
            "durable artifact import requires POSIX directory fsync support"
        )
    try:
        os.fsync(file_descriptor)
    except OSError as exc:
        raise ArtifactRepositoryError(f"{label} durability sync failed") from exc


@dataclass
class _TreeScanState:
    """Mutable counters kept out of the descriptor-relative traversal logic."""

    limits: ArtifactRepositoryLimits
    source_device: int
    entries: list[_TreeEntry]
    directories: set[str]
    byte_length: int = 0
    entry_count: int = 0

    def observe_entry(self, relative: tuple[str, ...]) -> str:
        self.entry_count += 1
        if self.entry_count > self.limits.max_entries:
            raise ArtifactValidationError("Run tree exceeds the configured entry-count bound")
        if len(relative) > self.limits.max_depth:
            raise ArtifactValidationError("Run tree exceeds the configured depth bound")
        relative_path = PurePosixPath(*relative).as_posix()
        try:
            relative_path.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ArtifactValidationError("Run tree entry cannot be inspected") from exc
        return relative_path

    def require_regular_file_capacity(self, observed: os.stat_result) -> None:
        if len(self.entries) >= self.limits.max_files:
            raise ArtifactValidationError("Run tree exceeds the configured file-count bound")
        if observed.st_size > self.limits.max_file_bytes:
            raise ArtifactValidationError("Run file exceeds the configured size bound")

    def add_regular_file(self, *, path: str, size: int, digest: str) -> None:
        try:
            entry = _TreeEntry(path=path, size=size, sha256=digest)
        except ValidationError as exc:
            raise ArtifactValidationError("Run tree entry metadata is invalid") from exc
        self.entries.append(entry)
        self.byte_length += size

    def finish(self, *, reject_untracked_directories: bool) -> _ScannedTree:
        ordered = tuple(sorted(self.entries, key=lambda item: item.path))
        if not ordered:
            raise ArtifactValidationError("Run tree must contain at least one regular file")
        if reject_untracked_directories:
            expected_directories = {
                parent.as_posix()
                for entry in ordered
                for parent in PurePosixPath(entry.path).parents
                if parent != PurePosixPath(".")
            }
            if self.directories != expected_directories:
                raise ArtifactValidationError(
                    "Run tree contains directories outside its canonical file tree"
                )
        return _ScannedTree(entries=ordered, byte_length=self.byte_length)


class _DescriptorTreeScanner:
    """Bounded tree walker that never resolves a child outside an opened parent fd."""

    def __init__(self, limits: ArtifactRepositoryLimits) -> None:
        self._limits = limits
        self._directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            self._directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            self._directory_flags |= os.O_NOFOLLOW

    def scan(
        self,
        root: Path,
        *,
        copy_to: Path | None = None,
        reject_untracked_directories: bool | None = None,
    ) -> _ScannedTree:
        source_fd, root_opened = self._open_root(root, label="Run tree root")
        destination_fd: int | None = None
        destination_opened: os.stat_result | None = None
        try:
            if copy_to is not None:
                destination_fd, destination_opened = self._open_root(
                    copy_to,
                    label="private copy root",
                )
            state = _TreeScanState(
                limits=self._limits,
                source_device=root_opened.st_dev,
                entries=[],
                directories=set(),
            )
            self._walk(source_fd, destination_fd, (), state)
            self._verify_root(root, source_fd, root_opened)
            if destination_fd is not None and destination_opened is not None:
                assert copy_to is not None
                self._verify_destination_root(copy_to, destination_fd, destination_opened)
            reject_directories = (
                copy_to is None
                if reject_untracked_directories is None
                else reject_untracked_directories
            )
            return state.finish(reject_untracked_directories=reject_directories)
        finally:
            if destination_fd is not None:
                os.close(destination_fd)
            os.close(source_fd)

    def _open_root(self, root: Path, *, label: str) -> tuple[int, os.stat_result]:
        try:
            observed = root.lstat()
            descriptor = os.open(root, self._directory_flags)
        except OSError as exc:
            raise ArtifactValidationError(f"{label} cannot be opened safely") from exc
        try:
            opened = os.fstat(descriptor)
            _require_same_entry(observed, opened)
            if not stat.S_ISDIR(opened.st_mode):
                raise ArtifactValidationError(f"{label} must remain a directory")
            return descriptor, opened
        except BaseException:
            os.close(descriptor)
            raise

    def _walk(
        self,
        source_fd: int,
        destination_fd: int | None,
        relative_parts: tuple[str, ...],
        state: _TreeScanState,
    ) -> bool:
        contains_file = False
        try:
            with os.scandir(source_fd) as iterator:
                for entry in iterator:
                    contains_file |= self._visit_entry(
                        source_fd,
                        destination_fd,
                        relative_parts,
                        entry.name,
                        state,
                    )
            if destination_fd is not None:
                _fsync_open_directory(destination_fd, label="copied Run directory")
            return contains_file
        except OSError as exc:
            raise ArtifactValidationError("Run tree cannot be enumerated") from exc

    def _visit_entry(
        self,
        source_fd: int,
        destination_fd: int | None,
        relative_parts: tuple[str, ...],
        name: str,
        state: _TreeScanState,
    ) -> bool:
        relative = (*relative_parts, name)
        if not relative_parts and name == _TRANSIENT_RUN_LOCK_NAME:
            raise ArtifactValidationError(
                "Run tree cannot contain transient mutation lock metadata"
            )
        relative_path = state.observe_entry(relative)
        observed = self._inspect_entry(source_fd, name)
        if observed.st_dev != state.source_device:
            raise ArtifactValidationError("Run tree cannot cross filesystem mount boundaries")
        if stat.S_ISLNK(observed.st_mode):
            raise ArtifactValidationError("Run trees cannot contain symbolic links")
        if stat.S_ISDIR(observed.st_mode):
            state.directories.add(relative_path)
            return self._visit_directory(
                source_fd,
                destination_fd,
                relative,
                name,
                observed,
                state,
            )
        if not stat.S_ISREG(observed.st_mode):
            raise ArtifactValidationError("Run trees cannot contain special files")
        return self._visit_regular_file(
            source_fd,
            destination_fd,
            relative_path,
            name,
            observed,
            state,
        )

    @staticmethod
    def _inspect_entry(source_fd: int, name: str) -> os.stat_result:
        try:
            return os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError as exc:
            raise ArtifactValidationError("Run tree entry cannot be inspected") from exc

    def _visit_directory(
        self,
        source_fd: int,
        destination_fd: int | None,
        relative: tuple[str, ...],
        name: str,
        observed: os.stat_result,
        state: _TreeScanState,
    ) -> bool:
        child_source_fd = self._open_child_directory(source_fd, name, observed)
        child_destination_fd: int | None = None
        try:
            if destination_fd is not None:
                os.mkdir(name, mode=0o700, dir_fd=destination_fd)
                child_destination_fd = self._open_destination_directory(destination_fd, name)
            contains_file = self._walk(
                child_source_fd,
                child_destination_fd,
                relative,
                state,
            )
            self._verify_child_directory(source_fd, child_source_fd, name, observed)
        except OSError as exc:
            raise ArtifactValidationError("Run directory changed while being copied") from exc
        finally:
            if child_destination_fd is not None:
                os.close(child_destination_fd)
            os.close(child_source_fd)
        if destination_fd is not None and not contains_file:
            try:
                os.rmdir(name, dir_fd=destination_fd)
            except OSError as exc:
                raise ArtifactValidationError("empty Run directory cannot be normalized") from exc
        return contains_file

    def _open_child_directory(
        self,
        parent_fd: int,
        name: str,
        observed: os.stat_result,
    ) -> int:
        try:
            descriptor = os.open(name, self._directory_flags, dir_fd=parent_fd)
        except OSError as exc:
            raise ArtifactValidationError("Run directory cannot be opened safely") from exc
        try:
            opened = os.fstat(descriptor)
            _require_same_entry(observed, opened)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _open_destination_directory(self, parent_fd: int, name: str) -> int:
        return os.open(name, self._directory_flags, dir_fd=parent_fd)

    @staticmethod
    def _verify_child_directory(
        parent_fd: int,
        child_fd: int,
        name: str,
        opened: os.stat_result,
    ) -> None:
        final = os.fstat(child_fd)
        _require_same_entry(opened, final)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _require_same_entry(final, current)

    def _visit_regular_file(
        self,
        source_fd: int,
        destination_fd: int | None,
        relative_path: str,
        name: str,
        observed: os.stat_result,
        state: _TreeScanState,
    ) -> bool:
        if observed.st_nlink != 1:
            raise ArtifactValidationError("Run trees cannot contain hard-linked files")
        state.require_regular_file_capacity(observed)
        digest, size = self._stream_file(
            source_fd,
            name,
            destination_fd,
            initial_stat=observed,
            total_before=state.byte_length,
        )
        state.add_regular_file(path=relative_path, size=size, digest=digest)
        return True

    def _stream_file(
        self,
        source_directory_fd: int,
        name: str,
        destination_directory_fd: int | None,
        *,
        initial_stat: os.stat_result,
        total_before: int,
    ) -> tuple[str, int]:
        source_fd = self._open_source_file(source_directory_fd, name)
        destination_fd: int | None = None
        try:
            opened = os.fstat(source_fd)
            self._require_stable_regular_file(initial_stat, opened)
            if destination_directory_fd is not None:
                destination_fd = self._open_destination_file(
                    destination_directory_fd,
                    name,
                )
            digest, size = self._copy_file_contents(
                source_fd,
                destination_fd,
                total_before=total_before,
            )
            self._verify_streamed_file(
                source_directory_fd,
                source_fd,
                name,
                opened,
                size,
            )
            if destination_fd is not None:
                os.fsync(destination_fd)
            return digest, size
        except OSError as exc:
            raise ArtifactValidationError("Run file changed while being scanned") from exc
        finally:
            if destination_fd is not None:
                os.close(destination_fd)
            os.close(source_fd)

    @staticmethod
    def _open_source_file(source_directory_fd: int, name: str) -> int:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            return os.open(name, flags, dir_fd=source_directory_fd)
        except OSError as exc:
            raise ArtifactValidationError("Run file cannot be opened safely") from exc

    @staticmethod
    def _open_destination_file(destination_directory_fd: int, name: str) -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        return os.open(name, flags, 0o600, dir_fd=destination_directory_fd)

    @staticmethod
    def _require_stable_regular_file(
        initial: os.stat_result,
        opened: os.stat_result,
    ) -> None:
        _require_same_entry(initial, opened)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ArtifactValidationError("Run file changed type or link count during import")

    def _copy_file_contents(
        self,
        source_fd: int,
        destination_fd: int | None,
        *,
        total_before: int,
    ) -> tuple[str, int]:
        digest = sha256()
        size = 0
        while chunk := os.read(source_fd, _COPY_CHUNK_BYTES):
            size += len(chunk)
            self._require_stream_capacity(size=size, total_before=total_before)
            digest.update(chunk)
            if destination_fd is not None:
                _write_all(destination_fd, chunk)
        return digest.hexdigest(), size

    def _require_stream_capacity(self, *, size: int, total_before: int) -> None:
        if size > self._limits.max_file_bytes:
            raise ArtifactValidationError("Run file exceeds the configured size bound")
        if total_before + size > self._limits.max_total_bytes:
            raise ArtifactValidationError("Run tree exceeds the configured total-size bound")

    @staticmethod
    def _verify_streamed_file(
        source_directory_fd: int,
        source_fd: int,
        name: str,
        opened: os.stat_result,
        size: int,
    ) -> None:
        final = os.fstat(source_fd)
        _require_same_entry(opened, final)
        if size != final.st_size:
            raise ArtifactValidationError("Run file changed length while being read")
        try:
            current = os.stat(name, dir_fd=source_directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise ArtifactValidationError("Run file disappeared while being read") from exc
        _require_same_entry(final, current)

    @staticmethod
    def _verify_root(root: Path, source_fd: int, opened: os.stat_result) -> None:
        final = os.fstat(source_fd)
        _require_same_entry(opened, final)
        try:
            current = root.lstat()
        except OSError as exc:
            raise ArtifactValidationError("Run tree root disappeared during scan") from exc
        _require_same_entry(final, current)

    @staticmethod
    def _verify_destination_root(
        root: Path,
        destination_fd: int,
        opened: os.stat_result,
    ) -> None:
        final = os.fstat(destination_fd)
        _require_same_inode(opened, final)
        try:
            current = root.lstat()
        except OSError as exc:
            raise ArtifactValidationError("private copy root disappeared during scan") from exc
        _require_same_inode(final, current)


class _BoundedRegularFileReader:
    """Read one manifest through a no-follow descriptor and rebind its leaf path."""

    def __init__(self, *, max_bytes: int) -> None:
        self._max_bytes = max_bytes

    def read(
        self,
        path: Path,
        *,
        label: str,
        require_single_link: bool,
    ) -> bytes:
        observed = self._inspect_initial(path, label=label, require_single_link=require_single_link)
        descriptor = self._open(path, label=label)
        require_stable = _require_same_entry if require_single_link else _require_same_file_content
        try:
            opened = os.fstat(descriptor)
            require_stable(observed, opened)
            content, size = self._read_chunks(descriptor, label=label)
            final = os.fstat(descriptor)
            require_stable(opened, final)
            if size != final.st_size:
                raise ArtifactValidationError(f"{label} changed while being read")
            current = self._inspect_final(path, label=label)
            require_stable(final, current)
            return content
        finally:
            os.close(descriptor)

    def _inspect_initial(
        self,
        path: Path,
        *,
        label: str,
        require_single_link: bool,
    ) -> os.stat_result:
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
        if observed.st_size > self._max_bytes:
            raise ArtifactValidationError(f"{label} exceeds the manifest size bound")
        return observed

    @staticmethod
    def _open(path: Path, *, label: str) -> int:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            return os.open(path, flags)
        except OSError as exc:
            raise ArtifactValidationError(f"{label} cannot be opened safely") from exc

    def _read_chunks(self, descriptor: int, *, label: str) -> tuple[bytes, int]:
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, _COPY_CHUNK_BYTES):
            size += len(chunk)
            if size > self._max_bytes:
                raise ArtifactValidationError(f"{label} exceeds the manifest size bound")
            chunks.append(chunk)
        return b"".join(chunks), size

    @staticmethod
    def _inspect_final(path: Path, *, label: str) -> os.stat_result:
        try:
            return path.lstat()
        except OSError as exc:
            raise ArtifactValidationError(f"{label} changed while being read") from exc


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
        self._staging_consume_lock = threading.Lock()
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
            # A consumer may claim this capability only after an admitting database
            # commit. Serialize the source copy with that claim so cleanup cannot
            # tear down a Run while another exact idempotent admission is scanning it.
            with self._locked_staging_root():
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

    def reserve_staging(self, staging_id: str) -> None:
        """Reserve one empty, private directory for an opaque Worker capability.

        The caller never receives a filesystem path. Repeating the exact reservation
        is safe only while the directory remains empty; once output exists, issuance
        cannot silently reuse it for another execution.
        """

        if not _DIRECTORY_FSYNC_SUPPORTED:
            raise ArtifactRepositoryError(
                "durable artifact staging requires POSIX directory fsync support"
            )
        self._require_repository_layout()
        self._require_directory(self.staging_root, label="staging root")
        self._require_private_owner_directory(self.staging_root, label="staging root")
        self._validate_staging_id(staging_id)
        destination = self.staging_root / staging_id
        try:
            destination.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError:
            self._require_directory(destination, label="reserved staging directory")
            self._require_private_owner_directory(
                destination,
                label="reserved staging directory",
            )
            try:
                if any(destination.iterdir()):
                    raise ArtifactConflict("reserved staging capability already contains output")
            except OSError as exc:
                raise ArtifactValidationError(
                    "reserved staging directory cannot be inspected"
                ) from exc
        self._require_directory(destination, label="reserved staging directory")
        self._require_private_owner_directory(
            destination,
            label="reserved staging directory",
        )
        self._fsync_directory(destination, label="reserved staging directory")
        self._fsync_directory(self.staging_root, label="staging root")

    def stage_managed_run_copy(self, *, staging_id: str, source: ArtifactRef) -> Path:
        """Atomically stage a private mutable copy of one verified managed Run.

        This server-only path is used to derive a new immutable Artifact without
        ever extending the admitted source object in place.
        """

        if not _DIRECTORY_FSYNC_SUPPORTED:
            raise ArtifactRepositoryError(
                "durable artifact staging requires POSIX directory fsync support"
            )
        self._require_repository_layout()
        self._require_directory(self.staging_root, label="staging root")
        self._require_private_owner_directory(self.staging_root, label="staging root")
        self._validate_staging_id(staging_id)
        snapshot = self.resolve(source)
        destination = self.staging_root / staging_id
        if self._lexists(destination):
            raise ArtifactConflict("projection staging capability already exists")

        temporary_root = Path(mkdtemp(prefix=".managed-copy-", dir=self.staging_root))
        copied_run = temporary_root / "run"
        copied_run.mkdir(mode=0o700)
        try:
            copied_tree = self._scan_tree(snapshot.path, copy_to=copied_run)
            if (
                copied_tree.byte_length != source.byte_length
                or copied_tree.digest != source.content_digest
            ):
                raise ArtifactValidationError("managed source changed while being copied")
            self._verify_managed_run_integrity(copied_run, ref=source)
            if self._scan_tree(copied_run) != copied_tree:
                raise ArtifactValidationError("staged managed copy changed during verification")
            try:
                os.rename(copied_run, destination)
            except OSError as exc:
                raise ArtifactRepositoryError("managed copy staging publish failed") from exc
            self._fsync_directory(destination, label="staged managed Run copy")
            self._fsync_directory(self.staging_root, label="staging root")
            return destination
        finally:
            if self._lexists(temporary_root):
                shutil.rmtree(temporary_root)

    def release_staging_reservation(self, staging_id: str) -> bool:
        """Remove one empty staging reservation without deleting Worker output.

        Returns ``True`` when this call removed the reservation and ``False`` when
        it was already absent. A non-directory or non-empty capability fails closed;
        rollback cleanup must never erase output that may have been produced.
        """

        self._require_directory(self.staging_root, label="staging root")
        self._require_private_owner_directory(self.staging_root, label="staging root")
        self._validate_staging_id(staging_id)
        destination = self.staging_root / staging_id
        try:
            observed = destination.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise ArtifactValidationError("reserved staging directory cannot be inspected") from exc
        if not stat.S_ISDIR(observed.st_mode):
            raise ArtifactValidationError("reserved staging capability must be a real directory")
        self._require_private_owner_directory(
            destination,
            label="reserved staging directory",
        )
        try:
            destination.rmdir()
        except FileNotFoundError:
            return False
        except OSError as exc:
            if exc.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                raise ArtifactConflict(
                    "reserved staging capability contains output and cannot be released"
                ) from exc
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ArtifactValidationError(
                    "reserved staging capability must remain a real directory"
                ) from exc
            raise ArtifactRepositoryError("staging reservation release failed") from exc
        self._fsync_directory(self.staging_root, label="staging root")
        return True

    def consume_staged_run(self, *, staging_id: str, expected_ref: ArtifactRef) -> bool:
        """Delete a staged Run only when it still equals committed managed authority.

        Consumption is intentionally separate from :meth:`import_run`: callers must
        invoke it only after the database transaction that admits ``expected_ref``
        has committed, or after re-reading that same committed authority. The target
        is claimed by a descriptor-relative rename before deletion. A deterministic
        tombstone also lets a retry finish cleanup after a process crash between the
        rename and removal.

        Returns ``True`` when this call removed the Run and ``False`` when a prior
        successful call already removed it. Any identity, integrity, or content
        mismatch fails closed and preserves the staged tree.
        """

        if not _DIRECTORY_FSYNC_SUPPORTED or sys.platform == "win32":
            raise ArtifactRepositoryError(
                "durable artifact consumption requires POSIX directory locking and fsync"
            )
        if not isinstance(expected_ref, ArtifactRef):
            raise ArtifactValidationError("staged Run consumption requires an ArtifactRef")
        self._validate_staging_id(staging_id)
        self.resolve(expected_ref)

        tombstone_name = f"{_CONSUMING_STAGING_PREFIX}{staging_id}"
        with self._locked_staging_root() as staging_root_fd:
            stage_exists = self._entry_exists(staging_root_fd, staging_id)
            tombstone_exists = self._entry_exists(staging_root_fd, tombstone_name)
            if stage_exists and tombstone_exists:
                raise ArtifactConflict(
                    "staged Run and its interrupted-consumption tombstone both exist"
                )
            if not stage_exists and not tombstone_exists:
                return False

            claimed_name = tombstone_name
            claimed_path = self.staging_root / claimed_name
            claimed_root: os.stat_result
            if stage_exists:
                staged_path = self.staging_root / staging_id
                staged_root = self._verify_staged_consumption_candidate(
                    staged_path,
                    expected_ref=expected_ref,
                )
                try:
                    os.rename(
                        staging_id,
                        claimed_name,
                        src_dir_fd=staging_root_fd,
                        dst_dir_fd=staging_root_fd,
                    )
                except OSError as exc:
                    raise ArtifactRepositoryError("staged Run consumption claim failed") from exc
                try:
                    claimed_root = os.stat(
                        claimed_name,
                        dir_fd=staging_root_fd,
                        follow_symlinks=False,
                    )
                    self._require_same_staged_root(
                        staged_root,
                        claimed_root,
                        allow_rename_ctime_change=True,
                    )
                except BaseException:
                    self._restore_consumption_claim(
                        staging_root_fd,
                        staging_id=staging_id,
                        claimed_name=claimed_name,
                    )
                    raise
                _fsync_open_directory(staging_root_fd, label="staging consumption claim")
            else:
                claimed_root = self._inspect_staging_entry(
                    staging_root_fd,
                    claimed_name,
                    label="interrupted staging consumption",
                )

            try:
                verified_root = self._verify_staged_consumption_candidate(
                    claimed_path,
                    expected_ref=expected_ref,
                )
                self._require_same_staged_root(claimed_root, verified_root)
                self._require_bound_staging_root(staging_root_fd)
            except BaseException:
                self._restore_consumption_claim(
                    staging_root_fd,
                    staging_id=staging_id,
                    claimed_name=claimed_name,
                )
                raise

            try:
                self._remove_claimed_staged_run(
                    staging_root_fd,
                    claimed_name=claimed_name,
                    expected_root=verified_root,
                )
            except ArtifactRepositoryError:
                raise
            except OSError as exc:
                raise ArtifactRepositoryError("staged Run removal failed") from exc
            return True

    def resolve(self, ref: ArtifactRef) -> ManagedArtifactSnapshot:
        """Freshly verify the manifest, complete tree, Run chain, and root digest."""

        self._require_repository_layout()
        storage_key, index_path, index_bytes, manifest = self._load_index_manifest(ref)
        run_path = self._resolve_object_run(manifest, index_bytes=index_bytes)
        self._verify_managed_tree(run_path, manifest=manifest, ref=ref)
        self._verify_managed_run_integrity(run_path, ref=ref)
        if self._read_regular_file(index_path, label="artifact index") != index_bytes:
            raise ArtifactValidationError("artifact manifest changed during resolution")
        return ManagedArtifactSnapshot(ref=ref, storage_key=storage_key, path=run_path)

    def _load_index_manifest(
        self,
        ref: ArtifactRef,
    ) -> tuple[str, Path, bytes, _ArtifactManifest]:
        if not isinstance(ref, ArtifactRef):
            raise ArtifactValidationError("resolve requires an ArtifactRef")
        if ref.repository_version != _REPOSITORY_VERSION:
            raise ArtifactValidationError(
                "artifact reference uses an unsupported repository version"
            )
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
        return storage_key, index_path, index_bytes, manifest

    def _resolve_object_run(
        self,
        manifest: _ArtifactManifest,
        *,
        index_bytes: bytes,
    ) -> Path:
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
        return run_path

    def _verify_managed_tree(
        self,
        run_path: Path,
        *,
        manifest: _ArtifactManifest,
        ref: ArtifactRef,
    ) -> None:
        observed_tree = self._scan_tree(run_path)
        if observed_tree.entries != manifest.tree:
            raise ArtifactValidationError("managed Run tree differs from its manifest")
        if observed_tree.byte_length != ref.byte_length:
            raise ArtifactValidationError("managed Run byte length differs from its reference")
        if observed_tree.digest != ref.content_digest:
            raise ArtifactValidationError("managed Run content digest differs from its reference")

    @staticmethod
    def _verify_managed_run_integrity(run_path: Path, *, ref: ArtifactRef) -> None:
        try:
            verification = verify_run_integrity(run_path)
        except (IndexError, OSError, RunIntegrityError, ValueError) as exc:
            raise ArtifactValidationError("managed Run integrity verification failed") from exc
        if verification.run_id != ref.run_id:
            raise ArtifactValidationError("managed Run identifier differs from its reference")
        if verification.root_digest != ref.integrity_root_digest:
            raise ArtifactValidationError("managed Run root digest differs from its reference")

    def _scan_tree(
        self,
        root: Path,
        *,
        copy_to: Path | None = None,
        reject_untracked_directories: bool | None = None,
    ) -> _ScannedTree:
        self._require_directory(root, label="Run tree root")
        if copy_to is not None:
            self._require_directory(copy_to, label="private copy root")
        return _DescriptorTreeScanner(self.limits).scan(
            root,
            copy_to=copy_to,
            reject_untracked_directories=reject_untracked_directories,
        )

    def _verify_staged_consumption_candidate(
        self,
        path: Path,
        *,
        expected_ref: ArtifactRef,
    ) -> os.stat_result:
        self._require_directory(path, label="staged Run consumption candidate")
        self._require_private_owner_directory(
            path,
            label="staged Run consumption candidate",
        )
        try:
            initial_root = path.lstat()
        except OSError as exc:
            raise ArtifactValidationError(
                "staged Run consumption candidate cannot be inspected"
            ) from exc
        initial_tree = self._scan_tree(path, reject_untracked_directories=False)
        try:
            verification = verify_run_integrity(path)
        except (IndexError, OSError, RunIntegrityError, ValueError) as exc:
            raise ArtifactValidationError(
                "staged Run consumption candidate failed integrity verification"
            ) from exc
        verified_tree = self._scan_tree(path, reject_untracked_directories=False)
        try:
            verified_root = path.lstat()
        except OSError as exc:
            raise ArtifactValidationError(
                "staged Run consumption candidate disappeared during verification"
            ) from exc
        self._require_same_staged_root(initial_root, verified_root)
        self._require_private_owner_directory(
            path,
            label="staged Run consumption candidate",
        )
        if initial_tree != verified_tree:
            raise ArtifactValidationError("staged Run changed during consumption verification")
        if (
            verified_tree.byte_length != expected_ref.byte_length
            or verified_tree.digest != expected_ref.content_digest
            or verification.run_id != expected_ref.run_id
            or verification.root_digest != expected_ref.integrity_root_digest
        ):
            raise ArtifactConflict("staged Run no longer matches committed Artifact authority")
        return verified_root

    @contextmanager
    def _locked_staging_root(self) -> Iterator[int]:
        with self._staging_consume_lock:
            self._require_directory(self.staging_root, label="staging root")
            self._require_private_owner_directory(self.staging_root, label="staging root")
            flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
            try:
                observed = self.staging_root.lstat()
                descriptor = os.open(self.staging_root, flags)
            except OSError as exc:
                raise ArtifactRepositoryError("staging root cannot be locked safely") from exc
            try:
                opened = os.fstat(descriptor)
                _require_same_inode(observed, opened)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                self._require_bound_staging_root(descriptor)
                yield descriptor
            finally:
                os.close(descriptor)

    def _require_bound_staging_root(self, descriptor: int) -> None:
        opened = os.fstat(descriptor)
        try:
            current = self.staging_root.lstat()
        except OSError as exc:
            raise ArtifactValidationError("staging root was substituted") from exc
        _require_same_inode(opened, current)
        if not stat.S_ISDIR(opened.st_mode):
            raise ArtifactValidationError("staging root must remain a directory")
        self._require_private_owner_directory(self.staging_root, label="staging root")

    @staticmethod
    def _entry_exists(parent_fd: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise ArtifactValidationError("staging entry cannot be inspected") from exc
        return True

    @staticmethod
    def _inspect_staging_entry(parent_fd: int, name: str, *, label: str) -> os.stat_result:
        try:
            observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise ArtifactValidationError(f"{label} cannot be inspected") from exc
        if not stat.S_ISDIR(observed.st_mode):
            raise ArtifactValidationError(f"{label} must remain a real directory")
        return observed

    def _remove_claimed_staged_run(
        self,
        staging_root_fd: int,
        *,
        claimed_name: str,
        expected_root: os.stat_result,
    ) -> None:
        """Remove only the directory inode verified under the durable claim name."""

        observed = self._inspect_staging_entry(
            staging_root_fd,
            claimed_name,
            label="claimed staging consumption",
        )
        self._require_same_staged_root(expected_root, observed)
        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        claimed_fd = os.open(claimed_name, flags, dir_fd=staging_root_fd)
        try:
            opened = os.fstat(claimed_fd)
            self._require_same_staged_root(expected_root, opened)
            self._remove_open_directory_contents(claimed_fd)
            self._require_bound_staging_root(staging_root_fd)
            current = os.stat(
                claimed_name,
                dir_fd=staging_root_fd,
                follow_symlinks=False,
            )
            self._require_same_directory_inode(opened, current)
            os.rmdir(claimed_name, dir_fd=staging_root_fd)
        finally:
            os.close(claimed_fd)
        _fsync_open_directory(staging_root_fd, label="staging consumption removal")

    def _remove_open_directory_contents(self, directory_fd: int) -> None:
        try:
            with os.scandir(directory_fd) as iterator:
                names = sorted(entry.name for entry in iterator)
        except OSError as exc:
            raise ArtifactValidationError(
                "claimed staged Run cannot be enumerated for removal"
            ) from exc

        for name in names:
            observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(observed.st_mode):
                self._remove_open_child_directory(
                    directory_fd,
                    name=name,
                    observed=observed,
                )
                continue
            if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
                raise ArtifactValidationError(
                    "claimed staged Run changed type or link count during removal"
                )
            self._remove_open_regular_file(
                directory_fd,
                name=name,
                observed=observed,
            )

        try:
            with os.scandir(directory_fd) as iterator:
                if next(iterator, None) is not None:
                    raise ArtifactValidationError("claimed staged Run changed during removal")
        except OSError as exc:
            raise ArtifactValidationError(
                "claimed staged Run cannot be rechecked after removal"
            ) from exc
        _fsync_open_directory(directory_fd, label="staged Run directory removal")

    def _remove_open_child_directory(
        self,
        parent_fd: int,
        *,
        name: str,
        observed: os.stat_result,
    ) -> None:
        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        child_fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(child_fd)
            _require_same_entry(observed, opened)
            self._remove_open_directory_contents(child_fd)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            self._require_same_directory_inode(opened, current)
            os.rmdir(name, dir_fd=parent_fd)
        finally:
            os.close(child_fd)

    @staticmethod
    def _remove_open_regular_file(
        parent_fd: int,
        *,
        name: str,
        observed: os.stat_result,
    ) -> None:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            _require_same_entry(observed, opened)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            _require_same_entry(opened, current)
            os.unlink(name, dir_fd=parent_fd)
            if os.fstat(descriptor).st_nlink != 0:
                raise ArtifactValidationError("claimed staged Run file path changed during removal")
        finally:
            os.close(descriptor)

    @staticmethod
    def _require_same_directory_inode(
        before: os.stat_result,
        after: os.stat_result,
    ) -> None:
        before_identity = (
            before.st_dev,
            before.st_ino,
            stat.S_IFMT(before.st_mode),
            stat.S_IMODE(before.st_mode),
            before.st_uid,
            before.st_gid,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            stat.S_IFMT(after.st_mode),
            stat.S_IMODE(after.st_mode),
            after.st_uid,
            after.st_gid,
        )
        if before_identity != after_identity or not stat.S_ISDIR(after.st_mode):
            raise ArtifactValidationError(
                "claimed staged Run directory identity changed during removal"
            )

    @staticmethod
    def _require_same_staged_root(
        before: os.stat_result,
        after: os.stat_result,
        *,
        allow_rename_ctime_change: bool = False,
    ) -> None:
        if allow_rename_ctime_change:
            before_identity = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_nlink,
            )
            after_identity = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_nlink,
            )
            if before_identity != after_identity:
                raise ArtifactValidationError("staged Run root changed during claim")
        else:
            _require_same_entry(before, after)
        before_metadata = (before.st_mode, before.st_uid, before.st_gid)
        after_metadata = (after.st_mode, after.st_uid, after.st_gid)
        if before_metadata != after_metadata or not stat.S_ISDIR(after.st_mode):
            raise ArtifactValidationError("staged Run root identity changed")

    @staticmethod
    def _restore_consumption_claim(
        staging_root_fd: int,
        *,
        staging_id: str,
        claimed_name: str,
    ) -> None:
        try:
            os.stat(staging_id, dir_fd=staging_root_fd, follow_symlinks=False)
        except FileNotFoundError:
            try:
                os.rename(
                    claimed_name,
                    staging_id,
                    src_dir_fd=staging_root_fd,
                    dst_dir_fd=staging_root_fd,
                )
                _fsync_open_directory(staging_root_fd, label="staging consumption rollback")
            except OSError:
                return
        except OSError:
            return

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
        return _computed_artifact_id(
            producer_run_id=producer_run_id,
            run_id=run_id,
            media_type=media_type,
            schema_kind=schema_kind,
            byte_length=byte_length,
            content_digest=content_digest,
            integrity_root_digest=integrity_root_digest,
            created_by=created_by,
        )

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
        return _BoundedRegularFileReader(max_bytes=_MAX_MANIFEST_BYTES).read(
            path,
            label=label,
            require_single_link=require_single_link,
        )

    @staticmethod
    def _parse_manifest(content: bytes) -> _ArtifactManifest:
        try:
            manifest = _ArtifactManifest.model_validate_json(content)
        except (ValidationError, ValueError) as exc:
            raise ArtifactValidationError("artifact manifest is invalid") from exc
        if ManagedArtifactRepository._manifest_bytes(manifest) != content:
            raise ArtifactValidationError("artifact manifest is not canonically encoded")
        return manifest

    @staticmethod
    def _write_exclusive(path: Path, content: bytes) -> None:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            raise ArtifactRepositoryError("private artifact metadata creation failed") from exc
        try:
            try:
                _write_all(descriptor, content)
                os.fsync(descriptor)
            except OSError as exc:
                raise ArtifactRepositoryError(
                    "private artifact metadata durability sync failed"
                ) from exc
        finally:
            os.close(descriptor)

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
            _require_same_inode(before, opened)
            if not stat.S_ISDIR(opened.st_mode):
                raise ArtifactRepositoryError(f"{label} must remain a directory")
            _fsync_open_directory(descriptor, label=label)
            try:
                current = path.lstat()
            except OSError as exc:
                raise ArtifactRepositoryError(
                    f"{label} disappeared during durability sync"
                ) from exc
            _require_same_inode(opened, current)
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
        if _is_link_or_junction(raw):
            raise ValueError(f"{label} root cannot be a symbolic link or junction")
        missing_paths: list[Path] = []
        cursor = raw
        while not os.path.lexists(cursor):
            missing_paths.append(cursor)
            parent = cursor.parent
            if parent == cursor:
                raise ValueError(f"{label} root has no existing filesystem anchor")
            cursor = parent
        creation_chain = [*missing_paths, cursor] if missing_paths else []
        for missing in reversed(missing_paths):
            _create_private_directory(missing, label=label)
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
            if observed.st_mode & stat.S_IRWXU != stat.S_IRWXU:
                raise error_type(f"{label} must grant owner read, write, and search access")
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
