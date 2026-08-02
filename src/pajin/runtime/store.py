"""Append-only audit, artifact, and tamper-evident Run storage."""

from __future__ import annotations

import errno
import importlib
import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
import unicodedata
import weakref
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, BinaryIO
from uuid import uuid4

if sys.platform != "win32":
    import fcntl

from pydantic import BaseModel, ConfigDict, Field, model_validator

from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes

_HASH_PATTERN = r"^[a-f0-9]{64}$"
_GENERATED_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_INTEGRITY_API_VERSION = "pajin.dev/run-integrity/v1"
_CAMPAIGN_TERMINAL_EVENTS = frozenset(
    {
        "campaign.completed",
        "campaign.failed",
        "campaign.cancelled",
        "campaign.budget-exhausted",
    }
)
_RUN_MUTATION_LOCK_NAME = ".pajin-run.lock"
_RUN_LOCK_DIRECTORY_NAME = ".pajin-run-locks"
_RESERVED_ARTIFACTS = frozenset({"events.jsonl", "run-integrity.jsonl", _RUN_MUTATION_LOCK_NAME})
_RESERVED_ARTIFACT_KEYS = frozenset(
    unicodedata.normalize("NFC", path).casefold() for path in _RESERVED_ARTIFACTS
)
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_MAX_EVENT_LOG_BYTES = 64 * 1024 * 1024
_MAX_INTEGRITY_LOG_BYTES = 64 * 1024 * 1024
_MAX_AUDIT_EVENT_RECORD_BYTES = 4 * 1024 * 1024
_MAX_INTEGRITY_SEAL_RECORD_BYTES = 16 * 1024 * 1024
_MAX_AUDIT_EVENT_RECORDS = 4_000_000
_MAX_INTEGRITY_SEAL_RECORDS = 1_000_000
_MAX_PROVENANCE_JSON_BYTES = 16 * 1024 * 1024
_MAX_VERIFIED_SNAPSHOT_ARTIFACTS = 10_000
_MAX_VERIFIED_SNAPSHOT_ARTIFACT_BYTES = 64 * 1024 * 1024
_WINDOWS_INVALID_PATH_CHARACTERS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_PATH_STEMS = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
_MEDIA_TYPES = {
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".md": "text/markdown",
    ".txt": "text/plain",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
}


class _RunThreadLock:
    """Weakly registered same-process lock for one physical Run directory."""

    def __init__(self) -> None:
        self.lock = threading.RLock()


_RUN_THREAD_LOCKS_GUARD = threading.Lock()
_RUN_THREAD_LOCKS: weakref.WeakValueDictionary[str, _RunThreadLock] = weakref.WeakValueDictionary()


class RunIntegrityError(ValueError):
    """A Run's event chain, seal chain, or sealed artifact set is invalid."""


def _canonical_path_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _validated_relative_artifact_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("artifact path must be a non-empty string")
    if value != unicodedata.normalize("NFC", value):
        raise ValueError("artifact path must use NFC Unicode normalization")
    if "\\" in value or "\x00" in value:
        raise ValueError("artifact path contains a non-portable separator or NUL")
    parts = value.split("/")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("artifact path must be a normalized relative path")
    for part in parts:
        if any(unicodedata.category(character).startswith("C") for character in part):
            raise ValueError("artifact path cannot contain Unicode control or format characters")
        if any(character in _WINDOWS_INVALID_PATH_CHARACTERS for character in part):
            raise ValueError("artifact path contains a character forbidden by Windows filesystems")
        if part.endswith((" ", ".")):
            raise ValueError("artifact path components cannot end in a space or period")
        device_stem = part.split(".", 1)[0].rstrip(" ").casefold()
        if device_stem in _WINDOWS_RESERVED_PATH_STEMS:
            raise ValueError("artifact path contains a reserved Windows device name")
    return path.as_posix()


def _ensure_private_directory(path: Path, *, exist_ok: bool = True) -> None:
    if path.is_symlink():
        raise ValueError("RunStore directories cannot be symbolic links")
    try:
        path.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
    except FileExistsError:
        if not exist_ok:
            raise
        if not path.is_dir() or path.is_symlink():
            raise ValueError("RunStore path component must be a regular directory") from None
    if os.name == "posix":
        path.chmod(_PRIVATE_DIRECTORY_MODE)


def _strict_json_bytes(value: object) -> bytes:
    serialized = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    return (serialized + "\n").encode("utf-8")


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run_identity_key(run_path: Path) -> str:
    run_stat = run_path.stat()
    if not stat.S_ISDIR(run_stat.st_mode):
        raise RunIntegrityError("Run path must be an existing directory")
    if run_stat.st_ino:
        identity = f"{run_stat.st_dev}:{run_stat.st_ino}"
    else:  # pragma: no cover - fallback for filesystems without stable inode numbers
        identity = os.path.normcase(str(run_path.resolve()))
    return sha256(identity.encode("utf-8")).hexdigest()


def _thread_lock_for_run(run_path: Path) -> _RunThreadLock:
    key = _run_identity_key(run_path)
    with _RUN_THREAD_LOCKS_GUARD:
        shared = _RUN_THREAD_LOCKS.get(key)
        if shared is None:
            shared = _RunThreadLock()
            _RUN_THREAD_LOCKS[key] = shared
        return shared


def _run_lock_root_path() -> Path:
    """Return a stable per-user lock root outside every immutable Run tree."""

    try:
        temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    except OSError as exc:
        raise RunIntegrityError("Run mutation lock parent is unavailable") from exc
    try:
        temporary_stat = temporary_root.stat()
    except OSError as exc:
        raise RunIntegrityError("Run mutation lock parent cannot be inspected") from exc
    if not stat.S_ISDIR(temporary_stat.st_mode):
        raise RunIntegrityError("Run mutation lock parent must be a directory")
    getuid = getattr(os, "getuid", None)
    user_suffix = f"-{getuid()}" if getuid is not None else ""
    return temporary_root / f"{_RUN_LOCK_DIRECTORY_NAME}{user_suffix}"


def _private_run_lock_root(run_path: Path) -> Path:
    # ``run_path`` remains part of the API because the lock file name below is
    # keyed by the physical Run identity.  The directory itself deliberately
    # lives elsewhere: writing a sidecar into ``run_path.parent`` mutates the
    # canonical layout of content-addressed managed artifacts.
    del run_path
    lock_root = _run_lock_root_path()
    created = False
    try:
        lock_root.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
        created = True
    except FileExistsError:
        pass
    lock_root_stat = lock_root.lstat()
    if not stat.S_ISDIR(lock_root_stat.st_mode) or lock_root.is_symlink():
        raise RunIntegrityError("Run mutation lock root must be a real directory")
    getuid = getattr(os, "getuid", None)
    if getuid is not None and lock_root_stat.st_uid != getuid():
        raise PermissionError("Run mutation lock root is owned by another user")
    if os.name == "posix":
        lock_root.chmod(_PRIVATE_DIRECTORY_MODE)
        secured_stat = lock_root.lstat()
        if (secured_stat.st_dev, secured_stat.st_ino) != (
            lock_root_stat.st_dev,
            lock_root_stat.st_ino,
        ) or not stat.S_ISDIR(secured_stat.st_mode):
            raise RunIntegrityError("Run mutation lock root changed while being secured")
        if stat.S_IMODE(secured_stat.st_mode) != _PRIVATE_DIRECTORY_MODE:
            raise PermissionError("Run mutation lock root permissions are not private")
    if created:
        _fsync_directory(lock_root.parent)
    return lock_root


def _run_lock_path(run_path: Path) -> Path:
    lock_root = _private_run_lock_root(run_path)
    return lock_root / f"{_run_identity_key(run_path)}.lock"


def _validate_existing_run_lock(lock_path: Path) -> bool:
    try:
        lock_stat = lock_path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(lock_stat.st_mode) or lock_path.is_symlink():
        raise RunIntegrityError("Run mutation lock must be a regular file, not a symbolic link")
    return True


def _validate_open_run_lock(lock_path: Path, descriptor: int) -> None:
    descriptor_stat = os.fstat(descriptor)
    try:
        path_stat = lock_path.lstat()
    except FileNotFoundError as exc:
        raise RunIntegrityError("Run mutation lock disappeared while being opened") from exc
    if not stat.S_ISREG(descriptor_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
        raise RunIntegrityError("Run mutation lock must be a regular file")
    if (descriptor_stat.st_dev, descriptor_stat.st_ino) != (
        path_stat.st_dev,
        path_stat.st_ino,
    ):
        raise RunIntegrityError("Run mutation lock path changed while being opened")
    if descriptor_stat.st_nlink != 1:
        raise RunIntegrityError("Run mutation lock must not have additional hard links")
    getuid = getattr(os, "getuid", None)
    if getuid is not None and descriptor_stat.st_uid != getuid():
        raise PermissionError("Run mutation lock is owned by another user")
    if hasattr(os, "fchmod"):
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
    if os.name == "posix" and stat.S_IMODE(os.fstat(descriptor).st_mode) != _PRIVATE_FILE_MODE:
        raise PermissionError("Run mutation lock permissions are not private")


def _lock_run_handle(handle: BinaryIO) -> None:
    if sys.platform != "win32":
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return
    if os.fstat(handle.fileno()).st_size == 0:
        handle.write(b"\0")
        handle.flush()
        os.fsync(handle.fileno())
    msvcrt = importlib.import_module("msvcrt")
    while True:
        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise
            time.sleep(0.05)


def _unlock_run_handle(handle: BinaryIO) -> None:
    if sys.platform != "win32":
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return
    msvcrt = importlib.import_module("msvcrt")
    handle.seek(0)
    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


@contextmanager
def _advisory_run_lock(run_path: Path) -> Iterator[None]:
    lock_path = _run_lock_path(run_path)
    existed = _validate_existing_run_lock(lock_path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, _PRIVATE_FILE_MODE)
    except OSError as exc:
        if lock_path.is_symlink():
            raise RunIntegrityError("Run mutation lock cannot be a symbolic link") from exc
        raise
    try:
        _validate_open_run_lock(lock_path, descriptor)
    except Exception:
        os.close(descriptor)
        raise
    if not existed:
        _fsync_directory(lock_path.parent)
    with os.fdopen(descriptor, "r+b", buffering=0) as handle:
        _lock_run_handle(handle)
        try:
            yield
        finally:
            _unlock_run_handle(handle)


@contextmanager
def _serialized_run_mutation(run_path: Path) -> Iterator[None]:
    shared = _thread_lock_for_run(run_path)
    with shared.lock, _advisory_run_lock(run_path):
        yield


@contextmanager
def locked_run_snapshot(run_path: Path) -> Iterator[Path]:
    """Serialize one read snapshot with writers that cooperate through ``RunStore``.

    The lock prevents an append/seal pair from crossing a multi-file read. It is an
    advisory coordination boundary, not a substitute for regular-file identity and
    sealed-hash checks against non-cooperating filesystem mutation.
    """

    root = run_path.resolve()
    with _serialized_run_mutation(root):
        yield root


def _atomic_write_private(destination: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".pajin-write.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    descriptor_open = True
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor_open = False
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        if descriptor_open:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
            _fsync_directory(destination.parent)


def _atomic_create_private(destination: Path, content: bytes) -> None:
    """Install a complete private file exactly once without a replace window."""

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".pajin-create.",
        suffix=".create",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    descriptor_open = True
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor_open = False
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        if descriptor_open:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
            _fsync_directory(destination.parent)


def _append_private_line(path: Path, line: str) -> None:
    encoded = line.encode("utf-8")
    existed = path.exists()
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written < 1:
                raise OSError("append-only Run log write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if not existed:
        _fsync_directory(path.parent)


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _file_digest(path: Path) -> str:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise RunIntegrityError("Run artifact cannot be inspected while hashing") from exc
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
        raise RunIntegrityError("Run artifacts must be single-link regular files")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RunIntegrityError("Run artifact cannot be opened safely while hashing") from exc
    digest = sha256()
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise RunIntegrityError("Run artifact changed while being opened for hashing")
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
        _require_unchanged_open_file(
            path,
            handle.fileno(),
            opened,
            label="Run artifact",
        )
    return digest.hexdigest()


def _open_bounded_regular_file(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> tuple[int, os.stat_result]:
    """Open one real file without following a substituted leaf."""

    try:
        observed = path.lstat()
    except OSError as exc:
        raise RunIntegrityError(f"{label} cannot be inspected") from exc
    if not stat.S_ISREG(observed.st_mode):
        raise RunIntegrityError(f"{label} must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RunIntegrityError(f"{label} cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            observed.st_dev,
            observed.st_ino,
        ):
            raise RunIntegrityError(f"{label} changed while being opened")
        if opened.st_nlink != 1:
            raise RunIntegrityError(f"{label} must not have additional hard links")
        if opened.st_size > max_bytes:
            raise RunIntegrityError(f"{label} exceeds the {max_bytes}-byte limit")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened


def _require_unchanged_open_file(
    path: Path,
    descriptor: int,
    opened: os.stat_result,
    *,
    label: str,
) -> None:
    try:
        final_descriptor = os.fstat(descriptor)
        final_path = path.lstat()
    except OSError as exc:
        raise RunIntegrityError(f"{label} changed while being read") from exc
    if (
        not stat.S_ISREG(final_descriptor.st_mode)
        or not stat.S_ISREG(final_path.st_mode)
        or final_descriptor.st_nlink != 1
        or final_path.st_nlink != 1
        or (final_descriptor.st_dev, final_descriptor.st_ino) != (opened.st_dev, opened.st_ino)
        or (final_path.st_dev, final_path.st_ino) != (opened.st_dev, opened.st_ino)
        or (
            final_descriptor.st_size,
            final_descriptor.st_mtime_ns,
            final_descriptor.st_ctime_ns,
        )
        != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
    ):
        raise RunIntegrityError(f"{label} changed while being read")


def _read_bounded_regular_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    try:
        return read_bounded_regular_bytes(
            path,
            max_bytes=max_bytes,
            label=label,
        )
    except (OSError, ValueError) as exc:
        raise RunIntegrityError(f"{label} could not be read safely") from exc


def _bounded_jsonl_records(
    path: Path,
    *,
    label: str,
    max_file_bytes: int,
    max_record_bytes: int,
    max_records: int,
) -> Iterator[tuple[int, bytes]]:
    """Stream bounded UTF-8 JSONL records without materializing the whole log."""

    descriptor, opened = _open_bounded_regular_file(
        path,
        label=label,
        max_bytes=max_file_bytes,
    )
    with os.fdopen(descriptor, "rb") as handle:
        observed_bytes = 0
        sequence = 0
        while raw_line := handle.readline(max_record_bytes + 1):
            observed_bytes += len(raw_line)
            if observed_bytes > max_file_bytes:
                raise RunIntegrityError(f"{label} exceeds the {max_file_bytes}-byte limit")
            if len(raw_line) > max_record_bytes:
                raise RunIntegrityError(f"{label} record exceeds the {max_record_bytes}-byte limit")
            sequence += 1
            if sequence > max_records:
                raise RunIntegrityError(f"{label} exceeds the {max_records}-record limit")
            yield sequence, raw_line
        _require_unchanged_open_file(path, handle.fileno(), opened, label=label)


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: f"event_{uuid4().hex}")
    run_id: str
    sequence: int = Field(ge=1)
    event_type: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str | None = Field(default=None, pattern=_HASH_PATTERN)
    event_hash: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def require_aware_timestamp(self) -> AuditEvent:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("Audit Event timestamps must include a UTC offset or Z")
        return self

    def computed_hash(self) -> str:
        material = self.model_dump(mode="json", exclude={"event_hash"})
        return _canonical_digest(material)


class ArtifactProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str | None = None
    tool_id: str | None = None
    execution_id: str | None = None
    event_ids: list[str] = Field(default_factory=list)


class SealedArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str = Field(pattern=_HASH_PATTERN)
    size_bytes: int = Field(ge=0)
    media_type: str
    provenance: ArtifactProvenance | None = None


class RunIntegritySeal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_version: str = _INTEGRITY_API_VERSION
    seal_id: str = Field(default_factory=lambda: f"seal_{uuid4().hex}")
    run_id: str
    sequence: int = Field(ge=1)
    sealed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    previous_root_digest: str | None = Field(default=None, pattern=_HASH_PATTERN)
    event_count: int = Field(ge=1)
    event_head_hash: str = Field(pattern=_HASH_PATTERN)
    artifact_root_digest: str = Field(pattern=_HASH_PATTERN)
    artifacts: list[SealedArtifact] = Field(default_factory=list)
    root_digest: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def require_aware_timestamp(self) -> RunIntegritySeal:
        if self.sealed_at.tzinfo is None or self.sealed_at.utcoffset() is None:
            raise ValueError("Run seal timestamps must include a UTC offset or Z")
        return self

    def computed_artifact_root_digest(self) -> str:
        return _canonical_digest([artifact.model_dump(mode="json") for artifact in self.artifacts])

    def computed_root_digest(self) -> str:
        material = self.model_dump(mode="json", exclude={"root_digest"})
        return _canonical_digest(material)


class RunIntegrityVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    seal_count: int = Field(ge=1)
    artifact_count: int = Field(ge=0)
    event_count: int = Field(ge=1)
    root_digest: str = Field(pattern=_HASH_PATTERN)
    valid: bool = True


@dataclass(frozen=True, slots=True)
class VerifiedRunSnapshot:
    """One cooperatively serialized view of a fully sealed Run."""

    run_path: Path
    verification: RunIntegrityVerification
    events: tuple[AuditEvent, ...]
    seals: tuple[RunIntegritySeal, ...]
    artifacts: Mapping[str, bytes]

    def artifact_bytes(self, relative_path: str) -> bytes:
        """Return one requested artifact or fail if it was not part of the snapshot."""

        try:
            return self.artifacts[relative_path]
        except KeyError as exc:
            raise KeyError(f"artifact was not requested in this snapshot: {relative_path}") from exc


@dataclass(frozen=True)
class _IntegrityState:
    run_id: str
    events: list[AuditEvent]
    seals: list[RunIntegritySeal]
    sealed_paths: set[str]
    unsealed_paths: list[str]


def _load_events(events_path: Path, *, expected_run_id: str | None = None) -> list[AuditEvent]:
    if not events_path.is_file():
        raise RunIntegrityError("Run event stream is missing")

    events: list[AuditEvent] = []
    previous_hash: str | None = None
    run_id = expected_run_id
    for expected_sequence, line in _bounded_jsonl_records(
        events_path,
        label="Run event stream",
        max_file_bytes=_MAX_EVENT_LOG_BYTES,
        max_record_bytes=_MAX_AUDIT_EVENT_RECORD_BYTES,
        max_records=_MAX_AUDIT_EVENT_RECORDS,
    ):
        if not line.strip():
            raise RunIntegrityError("Run event stream contains a blank record")
        try:
            raw_event = parse_strict_json_bytes(
                line,
                label=f"Run Audit Event at sequence {expected_sequence}",
                max_bytes=_MAX_AUDIT_EVENT_RECORD_BYTES,
            )
            event = AuditEvent.model_validate(raw_event)
        except ValueError as exc:
            raise RunIntegrityError(f"invalid Audit Event at sequence {expected_sequence}") from exc
        if run_id is None:
            run_id = event.run_id
        if event.run_id != run_id:
            raise RunIntegrityError("Run event stream contains inconsistent run identifiers")
        if event.sequence != expected_sequence:
            raise RunIntegrityError("Run event sequence is not contiguous")
        if event.previous_hash != previous_hash:
            raise RunIntegrityError("Run event previous-hash link is invalid")
        if event.event_hash != event.computed_hash():
            raise RunIntegrityError("Run event hash does not match its canonical content")
        events.append(event)
        previous_hash = event.event_hash
    if not events:
        raise RunIntegrityError("Run event stream is empty")
    terminal_events = [
        event.event_type for event in events if event.event_type in _CAMPAIGN_TERMINAL_EVENTS
    ]
    if len(terminal_events) > 1:
        raise RunIntegrityError(
            "Run event stream contains multiple Campaign terminal events: "
            + ", ".join(terminal_events)
        )
    return events


def _load_seals(integrity_path: Path, *, expected_run_id: str) -> list[RunIntegritySeal]:
    if not integrity_path.is_file():
        return []

    seals: list[RunIntegritySeal] = []
    previous_root: str | None = None
    for expected_sequence, line in _bounded_jsonl_records(
        integrity_path,
        label="Run integrity log",
        max_file_bytes=_MAX_INTEGRITY_LOG_BYTES,
        max_record_bytes=_MAX_INTEGRITY_SEAL_RECORD_BYTES,
        max_records=_MAX_INTEGRITY_SEAL_RECORDS,
    ):
        if not line.strip():
            raise RunIntegrityError("Run integrity log contains a blank record")
        try:
            raw_seal = parse_strict_json_bytes(
                line,
                label=f"Run integrity seal at sequence {expected_sequence}",
                max_bytes=_MAX_INTEGRITY_SEAL_RECORD_BYTES,
            )
            seal = RunIntegritySeal.model_validate(raw_seal)
        except ValueError as exc:
            raise RunIntegrityError(f"invalid Run seal at sequence {expected_sequence}") from exc
        if seal.api_version != _INTEGRITY_API_VERSION:
            raise RunIntegrityError("unsupported Run integrity version")
        if seal.run_id != expected_run_id:
            raise RunIntegrityError("Run seal belongs to a different run")
        if seal.sequence != expected_sequence:
            raise RunIntegrityError("Run seal sequence is not contiguous")
        if seal.previous_root_digest != previous_root:
            raise RunIntegrityError("Run seal previous-root link is invalid")
        if seal.artifacts != sorted(seal.artifacts, key=lambda item: item.path):
            raise RunIntegrityError("Run seal artifacts are not canonically ordered")
        if seal.artifact_root_digest != seal.computed_artifact_root_digest():
            raise RunIntegrityError("Run seal artifact root does not match its artifact records")
        if seal.root_digest != seal.computed_root_digest():
            raise RunIntegrityError("Run seal root digest does not match its canonical content")
        seals.append(seal)
        previous_root = seal.root_digest
    if not seals:
        raise RunIntegrityError("Run integrity log is empty")
    return seals


class _EventProvenanceIndex:
    """Index event payload strings once for linear artifact provenance checks."""

    def __init__(self) -> None:
        self._references: dict[str, list[tuple[int, str]]] = {}

    def add(self, event: AuditEvent) -> None:
        stack: list[object] = [event.payload]
        scalars: set[str] = set()
        while stack:
            value = stack.pop()
            if isinstance(value, str):
                scalars.add(value)
            elif isinstance(value, list):
                stack.extend(value)
            elif isinstance(value, dict):
                stack.extend(value.values())
        for scalar in scalars:
            self._references.setdefault(scalar, []).append((event.sequence, event.event_id))

    @classmethod
    def from_events(cls, events: list[AuditEvent]) -> _EventProvenanceIndex:
        index = cls()
        for event in events:
            index.add(event)
        return index

    def event_ids(self, *values: str | None) -> list[str]:
        referenced: dict[int, str] = {}
        for value in values:
            if value is None:
                continue
            for sequence, event_id in self._references.get(value, ()):
                referenced[sequence] = event_id
        return [referenced[sequence] for sequence in sorted(referenced)]


def _artifact_provenance(
    path: Path,
    relative_path: str,
    event_index: _EventProvenanceIndex,
) -> ArtifactProvenance | None:
    request_id: str | None = None
    tool_id: str | None = None
    execution_id: str | None = None
    if relative_path.startswith("evidence/") and path.suffix.lower() == ".json":
        content = _read_bounded_regular_file(
            path,
            label="Run evidence provenance source",
            max_bytes=_MAX_PROVENANCE_JSON_BYTES,
        )
        try:
            raw = parse_strict_json_bytes(
                content,
                label="Run evidence provenance source",
                max_bytes=_MAX_PROVENANCE_JSON_BYTES,
            )
        except ValueError:
            raw = None
        if isinstance(raw, dict):
            request = raw.get("request")
            worker_job = raw.get("workerJob")
            if isinstance(request, dict):
                raw_request_id = request.get("request_id")
                raw_tool_id = request.get("tool_id")
                request_id = raw_request_id if isinstance(raw_request_id, str) else None
                tool_id = raw_tool_id if isinstance(raw_tool_id, str) else None
            if isinstance(worker_job, dict):
                raw_execution_id = worker_job.get("executionId")
                execution_id = raw_execution_id if isinstance(raw_execution_id, str) else None

    event_ids = event_index.event_ids(relative_path, request_id)
    if not any((request_id, tool_id, execution_id, event_ids)):
        return None
    return ArtifactProvenance(
        request_id=request_id,
        tool_id=tool_id,
        execution_id=execution_id,
        event_ids=event_ids,
    )


def _artifact_record(
    root: Path,
    relative_path: str,
    event_index: _EventProvenanceIndex,
) -> SealedArtifact:
    path = root / relative_path
    try:
        opened = path.lstat()
    except OSError as exc:
        raise RunIntegrityError(f"Run artifact cannot be inspected: {relative_path}") from exc
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
        raise RunIntegrityError("Run artifacts must be single-link regular files")
    digest = _file_digest(path)
    try:
        final = path.lstat()
    except OSError as exc:
        raise RunIntegrityError(f"Run artifact changed while hashing: {relative_path}") from exc
    if (
        not stat.S_ISREG(final.st_mode)
        or final.st_nlink != 1
        or (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        )
        != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
    ):
        raise RunIntegrityError(f"Run artifact changed while hashing: {relative_path}")
    media_type = _MEDIA_TYPES.get(path.suffix.lower(), "application/octet-stream")
    return SealedArtifact(
        path=relative_path,
        sha256=digest,
        size_bytes=final.st_size,
        media_type=media_type,
        provenance=_artifact_provenance(path, relative_path, event_index),
    )


def _artifact_paths(root: Path) -> list[str]:
    paths: list[str] = []
    canonical_paths: dict[str, str] = {}
    for candidate in root.rglob("*"):
        if candidate.is_symlink():
            raise RunIntegrityError("Run artifacts cannot contain symbolic links")
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if root != resolved and root not in resolved.parents:
            raise RunIntegrityError("Run artifact resolves outside the Run directory")
        relative = candidate.relative_to(root).as_posix()
        if relative in _RESERVED_ARTIFACTS:
            continue
        try:
            relative = _validated_relative_artifact_path(relative)
        except ValueError as exc:
            raise RunIntegrityError(
                f"Run artifact path is not portable: {candidate.relative_to(root).as_posix()}"
            ) from exc
        canonical = _canonical_path_key(relative)
        if canonical in _RESERVED_ARTIFACT_KEYS:
            raise RunIntegrityError("Run artifact aliases a reserved RunStore path")
        previous = canonical_paths.get(canonical)
        if previous is not None and previous != relative:
            raise RunIntegrityError(
                f"Run contains canonically colliding artifact paths: {previous}, {relative}"
            )
        canonical_paths[canonical] = relative
        paths.append(relative)
    return sorted(paths)


def _verify_sealed_artifact(
    *,
    root: Path,
    artifact: SealedArtifact,
    event_index: _EventProvenanceIndex,
    current_paths_by_key: dict[str, str],
    sealed_paths: set[str],
    sealed_paths_by_key: dict[str, str],
) -> tuple[str, str]:
    try:
        sealed_path = _validated_relative_artifact_path(artifact.path)
    except ValueError as exc:
        raise RunIntegrityError(
            f"Run seal contains a non-portable artifact path: {artifact.path}"
        ) from exc
    artifact_key = _canonical_path_key(sealed_path)
    previous_path = sealed_paths_by_key.get(artifact_key)
    if (
        artifact_key in _RESERVED_ARTIFACT_KEYS
        or artifact.path in sealed_paths
        or previous_path is not None
    ):
        raise RunIntegrityError("Run seal contains a duplicate or reserved artifact path")
    current_path = current_paths_by_key.get(artifact_key)
    if current_path is None:
        raise RunIntegrityError(f"sealed Run artifact is missing: {artifact.path}")
    if current_path != artifact.path:
        raise RunIntegrityError(f"sealed Run artifact path identity changed: {artifact.path}")
    candidate = (root / artifact.path).resolve()
    if root not in candidate.parents or not candidate.is_file() or candidate.is_symlink():
        raise RunIntegrityError(f"sealed Run artifact is missing: {artifact.path}")
    if _artifact_record(root, artifact.path, event_index) != artifact:
        raise RunIntegrityError(f"sealed Run artifact changed: {artifact.path}")
    return artifact.path, artifact_key


def _index_sealed_artifacts(
    *,
    root: Path,
    seal: RunIntegritySeal,
    event_index: _EventProvenanceIndex,
    current_paths_by_key: dict[str, str],
    sealed_paths: set[str],
    sealed_paths_by_key: dict[str, str],
) -> None:
    for artifact in seal.artifacts:
        artifact_path, artifact_key = _verify_sealed_artifact(
            root=root,
            artifact=artifact,
            event_index=event_index,
            current_paths_by_key=current_paths_by_key,
            sealed_paths=sealed_paths,
            sealed_paths_by_key=sealed_paths_by_key,
        )
        sealed_paths.add(artifact_path)
        sealed_paths_by_key[artifact_key] = artifact_path


def _integrity_state(run_path: Path, *, allow_extensions: bool) -> _IntegrityState:
    root = run_path.resolve()
    if not root.is_dir():
        raise RunIntegrityError("Run path must be an existing directory")
    events = _load_events(root / "events.jsonl")
    run_id = events[0].run_id
    seals = _load_seals(root / "run-integrity.jsonl", expected_run_id=run_id)
    if not seals and not allow_extensions:
        raise RunIntegrityError("Run has not been integrity-sealed")

    current_path_list = _artifact_paths(root)
    current_paths = set(current_path_list)
    current_paths_by_key = {
        _canonical_path_key(relative): relative for relative in current_path_list
    }
    sealed_paths: set[str] = set()
    sealed_paths_by_key: dict[str, str] = {}
    previous_event_count = 0
    indexed_event_count = 0
    event_index = _EventProvenanceIndex()
    for seal in seals:
        if seal.event_count < previous_event_count or seal.event_count > len(events):
            raise RunIntegrityError("Run seal references an invalid event checkpoint")
        if events[seal.event_count - 1].event_hash != seal.event_head_hash:
            raise RunIntegrityError("Run seal event checkpoint does not match the event chain")
        previous_event_count = seal.event_count
        while indexed_event_count < seal.event_count:
            event_index.add(events[indexed_event_count])
            indexed_event_count += 1
        _index_sealed_artifacts(
            root=root,
            seal=seal,
            event_index=event_index,
            current_paths_by_key=current_paths_by_key,
            sealed_paths=sealed_paths,
            sealed_paths_by_key=sealed_paths_by_key,
        )

    unsealed_paths = sorted(current_paths - sealed_paths)
    if not allow_extensions:
        if seals[-1].event_count != len(events):
            raise RunIntegrityError("Run event stream has unsealed appended events")
        if unsealed_paths:
            raise RunIntegrityError(f"Run contains unsealed artifacts: {', '.join(unsealed_paths)}")
    return _IntegrityState(
        run_id=run_id,
        events=events,
        seals=seals,
        sealed_paths=sealed_paths,
        unsealed_paths=unsealed_paths,
    )


def verify_run_integrity(run_path: Path) -> RunIntegrityVerification:
    """Verify every event link, seal link, and sealed file in one Run directory."""

    state = _integrity_state(run_path, allow_extensions=False)
    return _verification_from_state(state)


def load_verified_run_snapshot(
    run_path: Path,
    *,
    expected_run_id: str | None = None,
) -> VerifiedRunSnapshot:
    """Return verified events and seals from one cooperative read snapshot.

    RunStore writers use the same advisory lock. Non-cooperating filesystem
    mutation remains subject to the regular-file identity and sealed-hash checks;
    this API does not claim to make an arbitrary hostile filesystem transactional.
    """

    return load_verified_run_artifacts(
        run_path,
        requests={},
        expected_run_id=expected_run_id,
    )


def load_verified_run_artifacts(
    run_path: Path,
    *,
    requests: Mapping[str, int],
    expected_run_id: str | None = None,
) -> VerifiedRunSnapshot:
    """Load only requested sealed artifacts into one exact verified snapshot."""

    validated_requests = _validated_snapshot_requests(requests)
    root = run_path.resolve()
    with locked_run_snapshot(root):
        initial = _integrity_state(root, allow_extensions=False)
        initial_verification = _verification_from_state(initial)
        if expected_run_id is not None and initial_verification.run_id != expected_run_id:
            raise RunIntegrityError("verified Run identifier differs from the expected Run")
        initial_records = _sealed_artifact_records(initial.seals)
        loaded = _load_snapshot_artifact_bytes(
            root,
            validated_requests,
            initial_records,
        )

        final = _integrity_state(root, allow_extensions=False)
        final_verification = _verification_from_state(final)
        if (
            final_verification != initial_verification
            or final.events != initial.events
            or final.seals != initial.seals
            or final.sealed_paths != initial.sealed_paths
        ):
            raise RunIntegrityError("verified Run changed while its snapshot was loaded")
        final_records = _sealed_artifact_records(final.seals)
        _bind_snapshot_artifact_bytes(loaded, final_records)
        return VerifiedRunSnapshot(
            run_path=root,
            verification=final_verification.model_copy(deep=True),
            events=tuple(event.model_copy(deep=True) for event in final.events),
            seals=tuple(seal.model_copy(deep=True) for seal in final.seals),
            artifacts=MappingProxyType(dict(loaded)),
        )


def load_verified_run_events(
    run_path: Path,
    *,
    expected_run_id: str | None = None,
) -> tuple[AuditEvent, ...]:
    """Load a bounded, verified event tuple without exposing private parsers."""

    return load_verified_run_snapshot(
        run_path,
        expected_run_id=expected_run_id,
    ).events


def _validated_snapshot_requests(requests: Mapping[str, int]) -> dict[str, int]:
    if not isinstance(requests, Mapping):
        raise TypeError("verified artifact requests must be a mapping")
    if len(requests) > _MAX_VERIFIED_SNAPSHOT_ARTIFACTS:
        raise ValueError("verified artifact request count exceeds the configured limit")
    validated: dict[str, int] = {}
    canonical_paths: set[str] = set()
    for raw_path, max_bytes in requests.items():
        relative_path = _validated_relative_artifact_path(raw_path)
        canonical = _canonical_path_key(relative_path)
        if canonical in _RESERVED_ARTIFACT_KEYS:
            raise ValueError("verified artifact requests cannot include reserved Run paths")
        if canonical in canonical_paths:
            raise ValueError("verified artifact requests contain canonically duplicate paths")
        if (
            type(max_bytes) is not int
            or max_bytes < 1
            or max_bytes > _MAX_VERIFIED_SNAPSHOT_ARTIFACT_BYTES
        ):
            raise ValueError(
                "verified artifact byte limits must be positive integers no greater than "
                f"{_MAX_VERIFIED_SNAPSHOT_ARTIFACT_BYTES}"
            )
        canonical_paths.add(canonical)
        validated[relative_path] = max_bytes
    return dict(sorted(validated.items()))


def _sealed_artifact_records(
    seals: list[RunIntegritySeal],
) -> dict[str, SealedArtifact]:
    records = {artifact.path: artifact for seal in seals for artifact in seal.artifacts}
    if len(records) != sum(len(seal.artifacts) for seal in seals):
        raise RunIntegrityError("Run seal chain contains duplicate artifact records")
    return records


def _load_snapshot_artifact_bytes(
    root: Path,
    requests: dict[str, int],
    records: dict[str, SealedArtifact],
) -> dict[str, bytes]:
    loaded: dict[str, bytes] = {}
    for relative_path, max_bytes in requests.items():
        record = records.get(relative_path)
        if record is None:
            raise RunIntegrityError(
                f"verified artifact request is not sealed by this Run: {relative_path}"
            )
        try:
            content = read_bounded_regular_bytes(
                root / relative_path,
                max_bytes=max_bytes,
                label=f"sealed Run artifact {relative_path}",
                require_single_link=True,
            )
        except (OSError, ValueError) as exc:
            raise RunIntegrityError(
                f"sealed Run artifact could not be loaded: {relative_path}"
            ) from exc
        loaded[relative_path] = content
    _bind_snapshot_artifact_bytes(loaded, records)
    return loaded


def _bind_snapshot_artifact_bytes(
    loaded: Mapping[str, bytes],
    records: Mapping[str, SealedArtifact],
) -> None:
    for relative_path, content in loaded.items():
        record = records.get(relative_path)
        if (
            record is None
            or record.size_bytes != len(content)
            or record.sha256 != sha256(content).hexdigest()
        ):
            raise RunIntegrityError(
                f"loaded Run artifact differs from its final seal record: {relative_path}"
            )


def _verification_from_state(state: _IntegrityState) -> RunIntegrityVerification:
    last_seal = state.seals[-1]
    return RunIntegrityVerification(
        run_id=state.run_id,
        seal_count=len(state.seals),
        artifact_count=len(state.sealed_paths),
        event_count=len(state.events),
        root_digest=last_seal.root_digest,
    )


class RunStore:
    """Store and append integrity extensions under one isolated Run directory."""

    def __init__(self, run_id: str, path: Path) -> None:
        self.run_id = run_id
        self.path = path.resolve()
        self.evidence_path = self.path / "evidence"
        self.events_path = self.path / "events.jsonl"
        self.integrity_path = self.path / "run-integrity.jsonl"
        self._event_count: int | None = None
        self._event_head_hash: str | None = None
        self._campaign_terminal_event: str | None = None
        self._path_identities: dict[str, str] | None = None

    @classmethod
    def create(
        cls,
        root: Path,
        campaign_name: str,
        *,
        run_id: str | None = None,
    ) -> RunStore:
        campaign_component = _validated_relative_artifact_path(campaign_name)
        if "/" in campaign_component:
            raise ValueError("campaign name must be one portable path component")
        root_path = root.resolve()
        if not root_path.exists():
            root_path.mkdir(mode=_PRIVATE_DIRECTORY_MODE, parents=True)
        if not root_path.is_dir():
            raise ValueError("RunStore root must be a directory")
        for entry in root_path.iterdir():
            if (
                _canonical_path_key(entry.name) == _canonical_path_key(campaign_component)
                and entry.name != campaign_component
            ):
                raise RunIntegrityError(
                    "campaign output path collides after NFC and case-fold normalization: "
                    f"{campaign_component}, {entry.name}"
                )
        campaign_path = root_path / campaign_component
        _ensure_private_directory(campaign_path)
        _fsync_directory(root_path)
        run_id = run_id or cls.new_run_id()
        if re.fullmatch(_GENERATED_RUN_ID_PATTERN, run_id) is None:
            raise ValueError("provided RunStore identifier is not a generated Run ID")
        path = campaign_path / run_id
        _ensure_private_directory(path, exist_ok=False)
        evidence_path = path / "evidence"
        _ensure_private_directory(evidence_path, exist_ok=False)
        _fsync_directory(path)
        _fsync_directory(campaign_path)
        return cls(run_id=run_id, path=path)

    @staticmethod
    def new_run_id() -> str:
        """Generate a validated Run ID before provisioning a transactional Run directory."""

        return f"run_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}_{uuid4().hex[:8]}"

    def append_event(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        occurred_at: datetime | None = None,
    ) -> AuditEvent:
        with self._mutation():
            return self._append_event_locked(
                event_type,
                payload,
                occurred_at=occurred_at,
            )

    def append_unique_event(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        occurred_at: datetime | None = None,
        unique_by: str | None = None,
    ) -> AuditEvent:
        """Append one exact event type once across cooperating RunStore writers."""

        canonical_payload = payload or {}
        if unique_by is not None and (
            not isinstance(unique_by, str)
            or not unique_by
            or not isinstance(canonical_payload.get(unique_by), str)
            or not canonical_payload[unique_by]
        ):
            raise ValueError("unique Run event identity must name a non-empty string field")
        with self._mutation():
            same_type = (
                tuple(
                    event
                    for event in _load_events(
                        self.events_path,
                        expected_run_id=self.run_id,
                    )
                    if event.event_type == event_type
                )
                if self.events_path.exists()
                else ()
            )
            existing = (
                tuple(
                    event
                    for event in same_type
                    if event.payload.get(unique_by) == canonical_payload[unique_by]
                )
                if unique_by is not None
                else same_type
            )
            if existing:
                if len(existing) != 1 or existing[0].payload != canonical_payload:
                    raise RunIntegrityError(
                        f"unique Run event {event_type} conflicts with existing audit"
                    )
                return existing[0]
            return self._append_event_locked(
                event_type,
                canonical_payload,
                occurred_at=occurred_at,
            )

    def _append_event_locked(
        self,
        event_type: str,
        payload: dict[str, Any] | None,
        *,
        occurred_at: datetime | None,
    ) -> AuditEvent:
        assert self._event_count is not None
        if (
            event_type in _CAMPAIGN_TERMINAL_EVENTS
            and self._campaign_terminal_event is not None
        ):
            raise RunIntegrityError(
                f"Run already contains Campaign terminal event {self._campaign_terminal_event}"
            )
        sequence = self._event_count + 1
        event = AuditEvent(
            run_id=self.run_id,
            sequence=sequence,
            event_type=event_type,
            occurred_at=occurred_at or datetime.now(UTC),
            payload=payload or {},
            previous_hash=self._event_head_hash,
            event_hash="0" * 64,
        )
        event = event.model_copy(update={"event_hash": event.computed_hash()})
        _append_private_line(self.events_path, event.model_dump_json() + "\n")
        self._event_count = sequence
        self._event_head_hash = event.event_hash
        if event_type in _CAMPAIGN_TERMINAL_EVENTS:
            self._campaign_terminal_event = event_type
        return event

    def write_json(self, relative_path: str, data: Any) -> str:
        with self._mutation():
            destination = self._safe_destination(relative_path)
            self._require_unsealed(destination)
            content = _strict_json_bytes(data)
            self._prepare_destination_parent(destination)
            _atomic_write_private(destination, content)
            self._record_path_identity(destination)
            return destination.relative_to(self.path).as_posix()

    def write_json_create_only(self, relative_path: str, data: Any) -> str:
        """Atomically install one strict JSON artifact and never replace an existing path."""

        with self._mutation():
            destination = self._safe_destination(relative_path)
            self._require_unsealed(destination)
            content = _strict_json_bytes(data)
            self._prepare_destination_parent(destination)
            _atomic_create_private(destination, content)
            self._record_path_identity(destination)
            return destination.relative_to(self.path).as_posix()

    def artifact_exists(self, relative_path: str) -> bool:
        """Return whether one validated regular artifact path is already occupied."""

        destination = self._safe_destination(relative_path)
        return destination.exists()

    def write_text(self, relative_path: str, content: str) -> str:
        with self._mutation():
            destination = self._safe_destination(relative_path)
            self._require_unsealed(destination)
            if not isinstance(content, str):
                raise TypeError("RunStore text content must be a string")
            serialized = content if content.endswith("\n") else content + "\n"
            encoded = serialized.encode("utf-8")
            self._prepare_destination_parent(destination)
            _atomic_write_private(destination, encoded)
            self._record_path_identity(destination)
            return destination.relative_to(self.path).as_posix()

    def write_bytes(self, relative_path: str, content: bytes) -> str:
        """Write exact opaque evidence bytes without newline or JSON normalization."""

        with self._mutation():
            destination = self._safe_destination(relative_path)
            self._require_unsealed(destination)
            if not isinstance(content, bytes):
                raise TypeError("RunStore binary content must be bytes")
            self._prepare_destination_parent(destination)
            _atomic_write_private(destination, content)
            self._record_path_identity(destination)
            return destination.relative_to(self.path).as_posix()

    def seal(self) -> RunIntegritySeal:
        """Append a seal for every new artifact and event since the previous seal."""

        with self._mutation():
            return self._seal_locked()

    def _seal_locked(self) -> RunIntegritySeal:
        state = _integrity_state(self.path, allow_extensions=True)
        if state.run_id != self.run_id:
            raise RunIntegrityError("RunStore identifier differs from the Run event stream")
        previous = state.seals[-1] if state.seals else None
        if (
            previous is not None
            and not state.unsealed_paths
            and previous.event_count == len(state.events)
        ):
            raise RunIntegrityError("Run has no new artifacts or events to seal")
        event_index = _EventProvenanceIndex.from_events(state.events)
        artifacts = sorted(
            (
                _artifact_record(self.path, relative, event_index)
                for relative in state.unsealed_paths
            ),
            key=lambda item: item.path,
        )
        artifact_root = _canonical_digest(
            [artifact.model_dump(mode="json") for artifact in artifacts]
        )
        seal = RunIntegritySeal(
            run_id=self.run_id,
            sequence=len(state.seals) + 1,
            previous_root_digest=previous.root_digest if previous else None,
            event_count=len(state.events),
            event_head_hash=state.events[-1].event_hash,
            artifact_root_digest=artifact_root,
            artifacts=artifacts,
            root_digest="0" * 64,
        )
        seal = seal.model_copy(update={"root_digest": seal.computed_root_digest()})
        _append_private_line(self.integrity_path, seal.model_dump_json() + "\n")
        return seal

    @contextmanager
    def _mutation(self) -> Iterator[None]:
        with _serialized_run_mutation(self.path):
            self._rebase_mutation_state()
            yield

    def _rebase_mutation_state(self) -> None:
        self._path_identities = None
        self._rebase_event_state()

    def _rebase_event_state(self) -> None:
        if not self.events_path.exists():
            self._event_count = 0
            self._event_head_hash = None
            self._campaign_terminal_event = None
            return
        if self.events_path.is_symlink():
            raise RunIntegrityError("Run event stream cannot be a symbolic link")
        events = _load_events(self.events_path, expected_run_id=self.run_id)
        self._event_count = len(events)
        self._event_head_hash = events[-1].event_hash
        self._campaign_terminal_event = next(
            (event.event_type for event in events if event.event_type in _CAMPAIGN_TERMINAL_EVENTS),
            None,
        )

    def _require_unsealed(self, destination: Path) -> None:
        relative = destination.relative_to(self.path).as_posix()
        canonical = _canonical_path_key(relative)
        if canonical in _RESERVED_ARTIFACT_KEYS:
            raise ValueError(f"artifact path is reserved by RunStore: {relative}")
        observed = self._path_identity_index().get(canonical)
        if observed is not None and observed != relative:
            raise RunIntegrityError(
                "artifact path collides after NFC and case-fold normalization: "
                f"{relative}, {observed}"
            )
        if not self.integrity_path.exists():
            return
        seals = _load_seals(self.integrity_path, expected_run_id=self.run_id)
        if any(
            canonical == _canonical_path_key(artifact.path)
            for seal in seals
            for artifact in seal.artifacts
        ):
            raise RunIntegrityError(f"sealed Run artifact cannot be overwritten: {relative}")

    def _safe_destination(self, relative_path: str) -> Path:
        relative = _validated_relative_artifact_path(relative_path)
        components = relative.split("/")
        current = self.path
        relative_components: list[str] = []
        identities = self._path_identity_index()
        for index, component in enumerate(components):
            relative_components.append(component)
            component_path = "/".join(relative_components)
            observed = identities.get(_canonical_path_key(component_path))
            if observed is not None and observed != component_path:
                raise RunIntegrityError(
                    "artifact path component collides after NFC and case-fold "
                    f"normalization: {component_path}, {observed}"
                )
            candidate = current / component
            if candidate.is_symlink():
                raise ValueError("artifact path cannot contain symbolic links")
            is_final = index == len(components) - 1
            if candidate.exists() and not is_final and not candidate.is_dir():
                raise ValueError("artifact path parent must be a directory")
            if candidate.exists() and is_final and not candidate.is_file():
                raise ValueError("artifact destination must be a regular file")
            current = candidate
        return current

    def _prepare_destination_parent(self, destination: Path) -> None:
        relative_parent = destination.parent.relative_to(self.path)
        current = self.path
        if os.name == "posix":
            current.chmod(_PRIVATE_DIRECTORY_MODE)
        for component in relative_parent.parts:
            current /= component
            _ensure_private_directory(current)
            self._record_path_identity(current)

    def _path_identity_index(self) -> dict[str, str]:
        if self._path_identities is not None:
            return self._path_identities
        identities: dict[str, str] = {}
        for candidate in self.path.rglob("*"):
            if candidate.is_symlink():
                raise RunIntegrityError("Run paths cannot contain symbolic links")
            relative = candidate.relative_to(self.path).as_posix()
            if relative not in _RESERVED_ARTIFACTS:
                try:
                    relative = _validated_relative_artifact_path(relative)
                except ValueError as exc:
                    raise RunIntegrityError(
                        f"Run path is not portable: {candidate.relative_to(self.path).as_posix()}"
                    ) from exc
            canonical = _canonical_path_key(relative)
            previous = identities.get(canonical)
            if previous is not None and previous != relative:
                raise RunIntegrityError(
                    f"Run contains canonically colliding paths: {previous}, {relative}"
                )
            identities[canonical] = relative
        self._path_identities = identities
        return identities

    def _record_path_identity(self, path: Path) -> None:
        if self._path_identities is None:
            return
        relative = path.relative_to(self.path).as_posix()
        canonical = _canonical_path_key(relative)
        previous = self._path_identities.get(canonical)
        if previous is not None and previous != relative:
            raise RunIntegrityError(
                f"Run contains canonically colliding paths: {previous}, {relative}"
            )
        self._path_identities[canonical] = relative
