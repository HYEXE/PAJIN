"""Deterministic SARIF export from one exact verified validation authority."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import unicodedata
from _thread import LockType
from contextlib import suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from threading import Lock
from typing import NoReturn, SupportsIndex, final

from pajin import __version__
from pajin.domain.models import Finding, FindingSeverity
from pajin.runtime.pinned_workspace import pinned_workspace_relative_path
from pajin.runtime.safe_files import atomic_write_text_no_follow, read_bounded_regular_bytes
from pajin.runtime.store import load_verified_run_snapshot
from pajin.runtime.verified_snapshot import require_same_authority
from pajin.workflow.validation_artifacts import (
    ValidationSnapshotSemantics,
    load_validation_snapshot,
)

SARIF_EXPORT_API_VERSION = "pajin.dev/sarif-export/v1alpha1"
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_MEDIA_TYPE = "application/sarif+json"

_HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_MAX_FINDINGS = 1_000
_MAX_FINDING_SET_BYTES = 16 * 1024 * 1024
_MAX_SARIF_BYTES = 16 * 1024 * 1024
_MAX_TITLE_BYTES = 4 * 1024
_MAX_THREAT_CLASS_BYTES = 1_024
_MAX_SUMMARY_BYTES = 64 * 1024
_MAX_DETAIL_BYTES = 32 * 1024
_MAX_REMEDIATION_ITEMS = 100
_MAX_REMEDIATION_BYTES = 16 * 1024


def _canonical_json_bytes(value: object, *, label: str, max_bytes: int) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds the canonical byte limit")
    return encoded


@dataclass(frozen=True, slots=True)
class SarifExportProjection:
    """Serializable SARIF data without filesystem or write authority."""

    source_run_id: str
    source_root_digest: str
    finding_set_digest: str
    sarif_digest: str
    finding_count: int
    content: str


_VERIFIED_SARIF_FACTORY_TOKEN = object()
_DirectoryIdentity = tuple[int, int, int, int]


@final
class VerifiedSarifExport:
    """Opaque authority handle for one exact sealed validation Run projection."""

    __slots__ = (
        "_factory_token",
        "_projection",
        "_source_parent_identity",
        "_source_run_identity",
        "_source_run_path",
        "_state_lock",
        "_write_consumed",
    )

    _factory_token: object
    _projection: SarifExportProjection
    _source_parent_identity: _DirectoryIdentity
    _source_run_identity: _DirectoryIdentity
    _source_run_path: Path
    _state_lock: LockType
    _write_consumed: bool

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedSarifExport:
        raise TypeError(
            "VerifiedSarifExport is an opaque handle; use load_verified_sarif_export()"
        )

    def __init_subclass__(cls) -> None:
        raise TypeError("VerifiedSarifExport cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise AttributeError("VerifiedSarifExport is immutable")

    def __delattr__(self, _name: str) -> NoReturn:
        raise AttributeError("VerifiedSarifExport is immutable")

    @property
    def projection(self) -> SarifExportProjection:
        return self._projection

    @property
    def source_run_path(self) -> Path:
        return self._source_run_path

    @property
    def source_run_id(self) -> str:
        return self._projection.source_run_id

    @property
    def source_root_digest(self) -> str:
        return self._projection.source_root_digest

    @property
    def finding_set_digest(self) -> str:
        return self._projection.finding_set_digest

    @property
    def sarif_digest(self) -> str:
        return self._projection.sarif_digest

    @property
    def finding_count(self) -> int:
        return self._projection.finding_count

    @property
    def content(self) -> str:
        return self._projection.content

    def __eq__(self, other: object) -> bool:
        return type(other) is VerifiedSarifExport and _verified_export_key(
            self
        ) == _verified_export_key(other)

    def __hash__(self) -> int:
        return hash(_verified_export_key(self))

    def __repr__(self) -> str:
        return (
            "VerifiedSarifExport("
            f"source_run_path={self.source_run_path!r}, "
            f"source_run_id={self.source_run_id!r}, "
            f"source_root_digest={self.source_root_digest!r}, "
            f"finding_set_digest={self.finding_set_digest!r}, "
            f"sarif_digest={self.sarif_digest!r}, "
            f"finding_count={self.finding_count!r}, content=<redacted>)"
        )

    def __copy__(self) -> NoReturn:
        raise TypeError("VerifiedSarifExport authority handles cannot be copied")

    def __deepcopy__(self, _memo: object) -> NoReturn:
        raise TypeError("VerifiedSarifExport authority handles cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("VerifiedSarifExport authority handles cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("VerifiedSarifExport authority handles cannot be serialized")


def load_verified_sarif_export(
    run_path: Path,
    *,
    expected_run_id: str,
    expected_root_digest: str,
) -> VerifiedSarifExport:
    """Build a minimized SARIF document from independently replay-confirmed Findings only."""

    _require_identifier(expected_run_id, label="expected validation Run ID")
    if _HASH_PATTERN.fullmatch(expected_root_digest) is None:
        raise ValueError("expected validation Run root digest must be 64 lowercase hex characters")

    requested_root = Path(run_path)
    pinned_root = pinned_workspace_relative_path(
        requested_root,
        label="verified SARIF source Run path",
    )
    root = (
        pinned_root
        if pinned_root is not None
        else requested_root.expanduser().resolve(strict=True)
    )
    source_run_identity, source_parent_identity = _source_path_identities(root)
    authority = load_verified_run_snapshot(root, expected_run_id=expected_run_id)
    if authority.verification.root_digest != expected_root_digest:
        raise ValueError("sealed validation Run root digest differs from the expected Run")

    snapshot = load_validation_snapshot(root, verified_snapshot=authority)
    if snapshot.semantics is not ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY:
        raise ValueError("SARIF export requires verified independent replay validation artifacts")
    findings = snapshot.product_confirmed_findings
    if len(findings) > _MAX_FINDINGS:
        raise ValueError(f"SARIF export exceeds the {_MAX_FINDINGS}-Finding limit")

    projection = _build_sarif_export(
        source_run_path=root,
        source_run_id=authority.verification.run_id,
        source_root_digest=authority.verification.root_digest,
        findings=findings,
    )
    current = load_verified_run_snapshot(root, expected_run_id=expected_run_id)
    require_same_authority(
        authority,
        current,
        message="sealed validation Run changed while SARIF was exported",
    )
    current_run_identity, current_parent_identity = _source_path_identities(root)
    if (
        current_run_identity != source_run_identity
        or current_parent_identity != source_parent_identity
    ):
        raise ValueError("sealed validation Run path identity changed while SARIF was exported")
    return _new_verified_sarif_export(
        source_run_path=root,
        source_run_identity=source_run_identity,
        source_parent_identity=source_parent_identity,
        projection=projection,
    )


def write_verified_sarif_export(export: VerifiedSarifExport, output_path: Path) -> Path:
    """Write one fresh, exact verified projection outside its immutable source Run."""

    _require_verified_sarif_handle(export)
    output = _normalized_output_path(output_path)
    _require_output_outside_source(export, output)
    lock = object.__getattribute__(export, "_state_lock")
    with lock:
        if object.__getattribute__(export, "_write_consumed"):
            raise ValueError("Verified SARIF export write authority was already consumed")
        _validated_projection_bytes(object.__getattribute__(export, "_projection"))
        if _posix_output_available():
            _write_verified_sarif_posix(export, output)
        else:  # pragma: no cover - exercised by non-POSIX CI
            _write_verified_sarif_portable(export, output)
        object.__setattr__(export, "_write_consumed", True)
    return output


def _new_verified_sarif_export(
    *,
    source_run_path: Path,
    source_run_identity: _DirectoryIdentity,
    source_parent_identity: _DirectoryIdentity,
    projection: SarifExportProjection,
) -> VerifiedSarifExport:
    handle = object.__new__(VerifiedSarifExport)
    object.__setattr__(handle, "_factory_token", _VERIFIED_SARIF_FACTORY_TOKEN)
    object.__setattr__(handle, "_source_run_path", source_run_path)
    object.__setattr__(handle, "_source_run_identity", source_run_identity)
    object.__setattr__(handle, "_source_parent_identity", source_parent_identity)
    object.__setattr__(handle, "_projection", projection)
    object.__setattr__(handle, "_state_lock", Lock())
    object.__setattr__(handle, "_write_consumed", False)
    return handle


def _require_verified_sarif_handle(export: VerifiedSarifExport) -> None:
    if type(export) is not VerifiedSarifExport:
        raise TypeError("SARIF operation requires an exact verified export handle")
    try:
        token = object.__getattribute__(export, "_factory_token")
        projection = object.__getattribute__(export, "_projection")
        source_path = object.__getattribute__(export, "_source_run_path")
        source_identity = object.__getattribute__(export, "_source_run_identity")
        parent_identity = object.__getattribute__(export, "_source_parent_identity")
        state_lock = object.__getattribute__(export, "_state_lock")
        consumed = object.__getattribute__(export, "_write_consumed")
    except AttributeError as exc:
        raise TypeError("SARIF operation requires a factory-issued export handle") from exc
    if (
        token is not _VERIFIED_SARIF_FACTORY_TOKEN
        or type(projection) is not SarifExportProjection
        or not isinstance(source_path, Path)
        or not _is_directory_identity(source_identity)
        or not _is_directory_identity(parent_identity)
        or not isinstance(state_lock, LockType)
        or type(consumed) is not bool
    ):
        raise TypeError("SARIF operation requires a factory-issued export handle")


def _verified_export_key(export: VerifiedSarifExport) -> tuple[object, ...]:
    _require_verified_sarif_handle(export)
    projection = object.__getattribute__(export, "_projection")
    return (
        object.__getattribute__(export, "_source_run_path"),
        object.__getattribute__(export, "_source_run_identity"),
        object.__getattribute__(export, "_source_parent_identity"),
        projection.source_run_id,
        projection.source_root_digest,
        projection.finding_set_digest,
        projection.sarif_digest,
        projection.finding_count,
        projection.content,
    )


def _reload_verified_sarif_export(export: VerifiedSarifExport) -> VerifiedSarifExport:
    """Reload an exact factory handle and return only the canonical fresh authority."""

    _require_verified_sarif_handle(export)
    projection = object.__getattribute__(export, "_projection")
    current = load_verified_sarif_export(
        object.__getattribute__(export, "_source_run_path"),
        expected_run_id=projection.source_run_id,
        expected_root_digest=projection.source_root_digest,
    )
    if _verified_export_key(current) != _verified_export_key(export):
        raise ValueError("verified SARIF export authority changed")
    return current


def _validated_projection_bytes(projection: SarifExportProjection) -> bytes:
    if type(projection) is not SarifExportProjection:
        raise TypeError("SARIF projection has an invalid runtime type")
    encoded = projection.content.encode("utf-8", errors="strict")
    if len(encoded) > _MAX_SARIF_BYTES:
        raise ValueError("SARIF export exceeds the canonical byte limit")
    if sha256(encoded).hexdigest() != projection.sarif_digest:
        raise ValueError("SARIF export content differs from its verified digest")
    return encoded


def _directory_identity(status: os.stat_result) -> _DirectoryIdentity:
    if not stat.S_ISDIR(status.st_mode):
        raise ValueError("SARIF authority path component is not a directory")
    return status.st_dev, status.st_ino, status.st_mode, getattr(status, "st_uid", -1)


def _is_directory_identity(value: object) -> bool:
    return bool(
        type(value) is tuple
        and len(value) == 4
        and all(type(item) is int for item in value)
    )


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _posix_output_available() -> bool:
    required = (os.open, os.mkdir, os.rename, os.stat, os.unlink)
    return bool(
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and all(operation in os.supports_dir_fd for operation in required)
        and os.stat in os.supports_follow_symlinks
    )


def _open_directory_path(
    path: Path,
    *,
    create: bool,
    label: str,
    protected_identity: tuple[int, int] | None = None,
    reject_run_ancestors: bool = False,
) -> tuple[int, _DirectoryIdentity]:
    start = path.anchor if path.is_absolute() else "."
    components = path.parts[1:] if path.is_absolute() else path.parts
    try:
        descriptor = os.open(start, _directory_open_flags())
    except OSError as exc:
        raise ValueError(f"{label} anchor cannot be opened safely") from exc
    try:
        identity = _directory_identity(os.fstat(descriptor))
        _reject_protected_directory(identity, protected_identity, label=label)
        if reject_run_ancestors:
            _reject_run_root(descriptor, label=label)
        for component in components:
            child = _open_directory_component(
                descriptor,
                component,
                create=create,
                label=label,
            )
            os.close(descriptor)
            descriptor = child
            identity = _directory_identity(os.fstat(descriptor))
            _reject_protected_directory(identity, protected_identity, label=label)
            if reject_run_ancestors:
                _reject_run_root(descriptor, label=label)
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _open_directory_component(
    parent_fd: int,
    component: str,
    *,
    create: bool,
    label: str,
) -> int:
    if not component or component in {".", ".."} or "/" in component or "\x00" in component:
        raise ValueError(f"{label} has an invalid path component")
    _reject_casefold_collision(parent_fd, component, label=label)
    try:
        return os.open(component, _directory_open_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise ValueError(f"{label} path changed") from None
        with suppress(FileExistsError):
            os.mkdir(component, mode=0o700, dir_fd=parent_fd)
        try:
            return os.open(component, _directory_open_flags(), dir_fd=parent_fd)
        except OSError as exc:
            raise ValueError(f"{label} parent contains a symbolic link or alias") from exc
    except OSError as exc:
        raise ValueError(f"{label} parent contains a symbolic link or alias") from exc


def _reject_protected_directory(
    identity: _DirectoryIdentity,
    protected: tuple[int, int] | None,
    *,
    label: str,
) -> None:
    if protected is not None and identity[:2] == protected:
        raise ValueError(f"{label} overlaps the immutable source Run")


def _path_component_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _reject_casefold_collision(parent_fd: int, requested: str, *, label: str) -> None:
    requested_key = _path_component_key(requested)
    try:
        entries = os.listdir(parent_fd)
    except OSError as exc:
        raise ValueError(f"{label} parent cannot be inspected safely") from exc
    if any(_path_component_key(entry) == requested_key and entry != requested for entry in entries):
        raise ValueError(f"{label} parent contains a mixed-case or Unicode alias")


def _reject_run_root(directory_fd: int, *, label: str) -> None:
    try:
        entries = {_path_component_key(entry) for entry in os.listdir(directory_fd)}
    except OSError as exc:
        raise ValueError(f"{label} ancestor cannot be inspected safely") from exc
    if {"events.jsonl", "run-integrity.jsonl"}.issubset(entries):
        raise ValueError(f"{label} must not be inside any Run authority")


def _source_path_identities(root: Path) -> tuple[_DirectoryIdentity, _DirectoryIdentity]:
    if _posix_output_available():
        parent_fd, parent_identity = _open_directory_path(
            root.parent,
            create=False,
            label="sealed validation Run parent",
        )
        root_fd = -1
        try:
            root_fd = _open_directory_component(
                parent_fd,
                root.name,
                create=False,
                label="sealed validation Run",
            )
            return _directory_identity(os.fstat(root_fd)), parent_identity
        finally:
            if root_fd >= 0:
                os.close(root_fd)
            os.close(parent_fd)
    try:  # pragma: no cover - exercised by non-POSIX CI
        parent_status = root.parent.lstat()
        root_status = root.lstat()
    except OSError as exc:  # pragma: no cover - exercised by non-POSIX CI
        raise ValueError("sealed validation Run path cannot be inspected safely") from exc
    if root.is_symlink() or root.parent.is_symlink():  # pragma: no cover
        raise ValueError("sealed validation Run path must not be a symbolic link")
    return _directory_identity(root_status), _directory_identity(parent_status)


def _normalized_output_path(path: Path) -> Path:
    candidate = Path(path)
    pinned = pinned_workspace_relative_path(
        candidate,
        label="verified SARIF output path",
    )
    output = (
        pinned
        if pinned is not None
        else Path(os.path.abspath(os.fspath(candidate.expanduser())))
    )
    if not output.name or output.name in {".", ".."}:
        raise ValueError("SARIF export artifact path requires a filename")
    return output


def _require_output_outside_source(export: VerifiedSarifExport, output: Path) -> None:
    source = object.__getattribute__(export, "_source_run_path")
    if source.is_absolute() != output.is_absolute():
        raise ValueError("SARIF output path authority differs from the source Run")
    if output.is_absolute():
        try:
            resolved_output = output.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise ValueError("SARIF output path cannot be resolved safely") from exc
    else:
        resolved_output = output
    if _paths_overlap(source, resolved_output) or _casefold_paths_overlap(source, resolved_output):
        raise ValueError("SARIF output must be outside the immutable source Run")


def _paths_overlap(first: Path, second: Path) -> bool:
    return bool(
        first == second
        or first in second.parents
        or second in first.parents
    )


def _casefold_paths_overlap(first: Path, second: Path) -> bool:
    first_parts = tuple(unicodedata.normalize("NFC", item).casefold() for item in first.parts)
    second_parts = tuple(unicodedata.normalize("NFC", item).casefold() for item in second.parts)
    return bool(
        first_parts == second_parts
        or first_parts == second_parts[: len(first_parts)]
        or second_parts == first_parts[: len(second_parts)]
    )


def _directory_ancestry(
    descriptor: int,
    *,
    reject_run_roots: bool = False,
) -> tuple[tuple[int, int], ...]:
    current = os.dup(descriptor)
    identities: list[tuple[int, int]] = []
    try:
        while True:
            if reject_run_roots:
                _reject_run_root(current, label="SARIF export artifact")
            identity = _directory_identity(os.fstat(current))[:2]
            identities.append(identity)
            parent = os.open("..", _directory_open_flags(), dir_fd=current)
            parent_identity = _directory_identity(os.fstat(parent))[:2]
            if parent_identity == identity:
                os.close(parent)
                break
            os.close(current)
            current = parent
    finally:
        os.close(current)
    return tuple(identities)


def _require_current_output_parent(
    parent: Path,
    expected: _DirectoryIdentity,
) -> None:
    descriptor, current = _open_directory_path(
        parent,
        create=False,
        label="SARIF export artifact parent",
        reject_run_ancestors=True,
    )
    os.close(descriptor)
    if current != expected:
        raise ValueError("SARIF export artifact parent path changed")


def _require_replaceable_output_leaf(parent_fd: int, name: str) -> None:
    _reject_casefold_collision(parent_fd, name, label="SARIF export artifact")
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("SARIF export artifact path must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("SARIF export artifact path must be a regular file")


def _create_output_temporary(parent_fd: int, destination_name: str) -> tuple[int, str]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    for _attempt in range(32):
        name = f".{destination_name}.{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            os.fchmod(descriptor, 0o600)
        except BaseException:
            os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(name, dir_fd=parent_fd)
            raise
        return descriptor, name
    raise FileExistsError("SARIF export temporary filename allocation was exhausted")


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:  # pragma: no cover - defensive OS contract
            raise OSError("SARIF export artifact write made no progress")
        remaining = remaining[written:]


def _read_output_at(parent_fd: int, name: str, expected_size: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != expected_size
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ValueError("SARIF export artifact is not an exact private regular file")
        chunks: list[bytes] = []
        observed = 0
        while observed < expected_size:
            chunk = os.read(descriptor, min(1024 * 1024, expected_size - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
        final = os.fstat(descriptor)
        path_status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        revision = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        final_revision = (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
        path_revision = (
            path_status.st_dev,
            path_status.st_ino,
            path_status.st_size,
            path_status.st_mtime_ns,
        )
        if revision != final_revision or revision != path_revision:
            raise ValueError("SARIF export artifact changed during read-back verification")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_output_at(
    parent_fd: int,
    output: Path,
    parent_identity: _DirectoryIdentity,
    payload: bytes,
    expected_digest: str,
) -> None:
    descriptor = -1
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = _create_output_temporary(parent_fd, output.name)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _require_current_output_parent(output.parent, parent_identity)
        _require_replaceable_output_leaf(parent_fd, output.name)
        os.rename(
            temporary_name,
            output.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_name = None
        os.fsync(parent_fd)
        _require_current_output_parent(output.parent, parent_identity)
        persisted = _read_output_at(parent_fd, output.name, len(payload))
        if persisted != payload or sha256(persisted).hexdigest() != expected_digest:
            raise ValueError("SARIF export artifact differs after write verification")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_fd)


def _write_verified_sarif_posix(export: VerifiedSarifExport, output: Path) -> None:
    source_identity = object.__getattribute__(export, "_source_run_identity")[:2]
    parent_fd, parent_identity = _open_directory_path(
        output.parent,
        create=True,
        label="SARIF export artifact parent",
        protected_identity=source_identity,
        reject_run_ancestors=True,
    )
    try:
        if source_identity in _directory_ancestry(parent_fd, reject_run_roots=True):
            raise ValueError("SARIF output must be outside the immutable source Run")
        _require_replaceable_output_leaf(parent_fd, output.name)
        _before_verified_sarif_write(output)
        _require_current_output_parent(output.parent, parent_identity)
        _require_replaceable_output_leaf(parent_fd, output.name)
        current = _reload_verified_sarif_export(export)
        projection = object.__getattribute__(current, "_projection")
        payload = _validated_projection_bytes(projection)
        _write_output_at(
            parent_fd,
            output,
            parent_identity,
            payload,
            projection.sarif_digest,
        )
    finally:
        os.close(parent_fd)


def _write_verified_sarif_portable(export: VerifiedSarifExport, output: Path) -> None:
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_identity = _directory_identity(output.parent.lstat())
    _before_verified_sarif_write(output)
    if _directory_identity(output.parent.lstat()) != parent_identity:
        raise ValueError("SARIF export artifact parent path changed")
    current = _reload_verified_sarif_export(export)
    projection = object.__getattribute__(current, "_projection")
    payload = _validated_projection_bytes(projection)
    atomic_write_text_no_follow(output, projection.content, label="SARIF export artifact")
    if _directory_identity(output.parent.lstat()) != parent_identity:
        raise ValueError("SARIF export artifact parent path changed")
    persisted = read_bounded_regular_bytes(
        output,
        max_bytes=_MAX_SARIF_BYTES,
        label="SARIF export artifact",
        require_single_link=True,
    )
    if persisted != payload or sha256(persisted).hexdigest() != projection.sarif_digest:
        raise ValueError("SARIF export artifact differs after write verification")


def _before_verified_sarif_write(_output: Path) -> None:
    """Test seam immediately before final source reload and fd-relative write."""


def _build_sarif_export(
    *,
    source_run_path: Path,
    source_run_id: str,
    source_root_digest: str,
    findings: list[Finding],
) -> SarifExportProjection:
    _ = source_run_path  # A data-only projection intentionally carries no filesystem authority.
    _require_identifier(source_run_id, label="validation Run ID")
    if _HASH_PATTERN.fullmatch(source_root_digest) is None:
        raise ValueError("validation Run root digest must be 64 lowercase hex characters")
    if len(findings) > _MAX_FINDINGS:
        raise ValueError(f"SARIF export exceeds the {_MAX_FINDINGS}-Finding limit")

    finding_ids = [finding.finding_id for finding in findings]
    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("SARIF export requires unique Finding IDs")
    for finding_id in finding_ids:
        _require_identifier(finding_id, label="Finding ID")

    finding_payload = [finding.model_dump(mode="json") for finding in findings]
    finding_set_bytes = _canonical_json_bytes(
        finding_payload,
        label="SARIF source Finding set",
        max_bytes=_MAX_FINDING_SET_BYTES,
    )
    finding_set_digest = sha256(finding_set_bytes).hexdigest()

    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in sorted(findings, key=lambda item: item.finding_id):
        if not finding.validated:
            raise ValueError("SARIF export cannot include an unvalidated Finding")
        threat_class = _safe_text(
            finding.threat_class,
            label=f"Finding {finding.finding_id} threat class",
            max_bytes=_MAX_THREAT_CLASS_BYTES,
            single_line=True,
        )
        rule_id = _rule_id(threat_class)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": threat_class,
                "shortDescription": {"text": f"PAJIN confirmed {threat_class} finding"},
                "properties": {
                    "pajinThreatClass": threat_class,
                    "pajinThreatClassDigest": sha256(threat_class.encode("utf-8")).hexdigest(),
                },
            },
        )
        results.append(_sarif_result(finding, rule_id=rule_id))

    document: dict[str, object] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "automationDetails": {
                    "id": (f"pajin/sarif-export/v1alpha1/{source_run_id}/{source_root_digest[:16]}")
                },
                "tool": {
                    "driver": {
                        "name": "PAJIN",
                        "semanticVersion": __version__,
                        "rules": [rules[rule_id] for rule_id in sorted(rules)],
                    }
                },
                "results": results,
                "properties": {
                    "pajin": {
                        "apiVersion": SARIF_EXPORT_API_VERSION,
                        "sourceRunId": source_run_id,
                        "sourceRootDigest": source_root_digest,
                        "sourceFindingSetDigest": finding_set_digest,
                        "confirmationSemantics": (
                            ValidationSnapshotSemantics.VERIFIED_INDEPENDENT_REPLAY.value
                        ),
                        "redactionProfile": "pajin-minimized-finding-v1",
                        "excludedFindingFields": [
                            "target",
                            "rootCause",
                            "reproduction",
                            "evidence",
                        ],
                        "externalDeliveryPerformed": False,
                        "deliveryReceiptAuthority": False,
                        "issueMutationAuthority": False,
                        "siemIngestAuthority": False,
                        "soarActionAuthority": False,
                    }
                },
            }
        ],
    }
    content = (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    )
    encoded = content.encode("utf-8")
    if len(encoded) > _MAX_SARIF_BYTES:
        raise ValueError("SARIF export exceeds the canonical byte limit")
    return SarifExportProjection(
        source_run_id=source_run_id,
        source_root_digest=source_root_digest,
        finding_set_digest=finding_set_digest,
        sarif_digest=sha256(encoded).hexdigest(),
        finding_count=len(findings),
        content=content,
    )


def _sarif_result(finding: Finding, *, rule_id: str) -> dict[str, object]:
    finding_payload = finding.model_dump(mode="json")
    finding_digest = sha256(
        _canonical_json_bytes(
            finding_payload,
            label=f"Finding {finding.finding_id} fingerprint",
            max_bytes=_MAX_FINDING_SET_BYTES,
        )
    ).hexdigest()
    title = _safe_text(
        finding.title,
        label=f"Finding {finding.finding_id} title",
        max_bytes=_MAX_TITLE_BYTES,
        single_line=True,
    )
    summary = _safe_text(
        finding.summary,
        label=f"Finding {finding.finding_id} summary",
        max_bytes=_MAX_SUMMARY_BYTES,
    )
    properties: dict[str, object] = {
        "pajinFindingId": finding.finding_id,
        "pajinFindingDigest": finding_digest,
        "title": title,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "validated": True,
        "targetDigest": sha256(finding.target.encode("utf-8", errors="strict")).hexdigest(),
    }
    if finding.impact is not None:
        properties["impact"] = _safe_text(
            finding.impact,
            label=f"Finding {finding.finding_id} impact",
            max_bytes=_MAX_DETAIL_BYTES,
        )
    if finding.affected_component is not None:
        properties["affectedComponent"] = _safe_text(
            finding.affected_component,
            label=f"Finding {finding.finding_id} affected component",
            max_bytes=_MAX_DETAIL_BYTES,
        )
    if len(finding.remediation) > _MAX_REMEDIATION_ITEMS:
        raise ValueError(f"Finding {finding.finding_id} exceeds the remediation item limit")
    if finding.remediation:
        properties["remediation"] = [
            _safe_text(
                item,
                label=f"Finding {finding.finding_id} remediation",
                max_bytes=_MAX_REMEDIATION_BYTES,
            )
            for item in finding.remediation
        ]
    return {
        "ruleId": rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": summary},
        "partialFingerprints": {"pajinFinding/v1": finding_digest},
        "properties": properties,
    }


def _safe_text(value: str, *, label: str, max_bytes: int, single_line: bool = False) -> str:
    normalized = unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
    if not normalized:
        raise ValueError(f"{label} must not be empty")
    for character in normalized:
        category = unicodedata.category(character)
        if category in {"Cf", "Cs"} or (category == "Cc" and character not in {"\n", "\t"}):
            raise ValueError(f"{label} contains unsafe Unicode controls")
        if single_line and character in {"\n", "\t"}:
            raise ValueError(f"{label} must be a single line")
    try:
        encoded = normalized.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8 text") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds the export byte limit")
    return normalized


def _require_identifier(value: str, *, label: str) -> None:
    if _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a portable identifier")


def _rule_id(threat_class: str) -> str:
    digest = sha256(b"pajin-sarif-rule-v1\x00" + threat_class.encode("utf-8")).hexdigest()
    return f"PAJIN-{digest}"


def _sarif_level(severity: FindingSeverity) -> str:
    if severity in {FindingSeverity.CRITICAL, FindingSeverity.HIGH}:
        return "error"
    if severity is FindingSeverity.MEDIUM:
        return "warning"
    return "note"
