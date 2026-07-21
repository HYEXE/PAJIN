"""Symlink-safe atomic status-file replacement shared by Worker daemons."""

from __future__ import annotations

import errno
import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path
from typing import NoReturn

_MAX_STATUS_FILENAME_BYTES = 200
_MAX_STATUS_FILE_BYTES = 64 * 1024
_TEMPORARY_CREATE_ATTEMPTS = 16


def default_worker_status_path() -> Path:
    return Path.home() / ".pajin" / "status" / "worker-status.json"


def default_replay_worker_status_path() -> Path:
    return Path.home() / ".pajin" / "status" / "replay-worker-status.json"


def write_status_file(path: Path, payload: str, *, owner_label: str) -> None:
    """Replace one status leaf without following attacker-controlled leaves."""

    _require_secure_status_platform(owner_label=owner_label)
    _validate_status_leaf(path, owner_label=owner_label)
    parent_descriptor = _open_status_parent(
        path.parent,
        owner_label=owner_label,
        create=True,
    )
    temporary_name: str | None = None
    descriptor = -1
    try:
        descriptor, temporary_name = _create_temporary_status_file(
            parent_descriptor,
            destination_name=path.name,
            owner_label=owner_label,
        )
        handle = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
        descriptor = -1
        with handle:
            handle.write(payload)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = None
        os.fsync(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_descriptor)
        os.close(parent_descriptor)


def read_status_file(path: Path, *, owner_label: str) -> str:
    """Read one bounded regular status leaf without following links or devices."""

    _require_secure_status_platform(owner_label=owner_label)
    _validate_status_leaf(path, owner_label=owner_label)
    parent_descriptor = _open_status_parent(
        path.parent,
        owner_label=owner_label,
        create=False,
    )
    descriptor = -1
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError(f"{owner_label} status path must not be a symbolic link") from exc
            raise
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{owner_label} status path must be a regular file")
        if metadata.st_size > _MAX_STATUS_FILE_BYTES:
            raise ValueError(f"{owner_label} status file exceeds its byte limit")
        payload = _read_bounded_status_bytes(descriptor, owner_label=owner_label)
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"{owner_label} status file is not valid UTF-8") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _read_bounded_status_bytes(descriptor: int, *, owner_label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = _MAX_STATUS_FILE_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 8192))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > _MAX_STATUS_FILE_BYTES:
        raise ValueError(f"{owner_label} status file exceeds its byte limit")
    return payload


def _require_secure_status_platform(*, owner_label: str) -> None:
    if _secure_status_platform_available():
        return
    raise RuntimeError(
        f"{owner_label} secure status files require a POSIX dirfd platform; "
        "run the Worker in the Linux container or WSL"
    )


def _secure_status_platform_available(*, platform_name: str | None = None) -> bool:
    required_dir_fd_operations = (os.open, os.mkdir, os.rename, os.unlink)
    return bool(
        (os.name if platform_name is None else platform_name) == "posix"
        and hasattr(os, "geteuid")
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and all(operation in os.supports_dir_fd for operation in required_dir_fd_operations)
    )


def _validate_status_leaf(path: Path, *, owner_label: str) -> None:
    if (
        not path.name
        or path.name in {".", ".."}
        or len(path.name.encode("utf-8")) > _MAX_STATUS_FILENAME_BYTES
    ):
        raise ValueError(f"{owner_label} status path requires a bounded filename")


def _open_status_parent(
    parent: Path,
    *,
    owner_label: str,
    create: bool,
) -> int:
    canonical_parent, is_private_tmp_root = _canonical_status_parent(
        parent,
        owner_label=owner_label,
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open("/", flags)
    try:
        components = canonical_parent.parts[1:]
        for index, component in enumerate(components):
            next_descriptor = _open_or_create_directory_component(
                descriptor,
                component=component,
                flags=flags,
                owner_label=owner_label,
                create=create,
            )
            if index < len(components) - 1:
                _require_safe_status_ancestor(
                    next_descriptor,
                    owner_label=owner_label,
                )
            os.close(descriptor)
            descriptor = next_descriptor
        _require_safe_status_parent(
            descriptor,
            is_private_tmp_root=is_private_tmp_root,
            owner_label=owner_label,
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _canonical_status_parent(
    parent: Path,
    *,
    owner_label: str,
) -> tuple[Path, bool]:
    lexical_parent = Path(os.path.abspath(parent))
    system_tmp_alias = Path("/tmp")
    try:
        relative = lexical_parent.relative_to(system_tmp_alias)
    except ValueError:
        return lexical_parent, False
    trusted_tmp, is_private_tmp_root = _trusted_system_tmp_root(owner_label=owner_label)
    canonical = trusted_tmp.joinpath(*relative.parts)
    return canonical, is_private_tmp_root and not relative.parts


def _trusted_system_tmp_root(*, owner_label: str) -> tuple[Path, bool]:
    alias = Path("/tmp")
    try:
        alias_stat = os.lstat(alias)
        resolved = alias.resolve(strict=True)
        resolved_stat = os.stat(resolved, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"{owner_label} status system temporary root is invalid") from exc
    if not stat.S_ISDIR(resolved_stat.st_mode):
        raise ValueError(f"{owner_label} status system temporary root is not trusted")
    if stat.S_ISLNK(alias_stat.st_mode) and alias_stat.st_uid != 0:
        raise ValueError(f"{owner_label} status system temporary root is not trusted")
    root_owned_sticky = resolved_stat.st_uid == 0 and bool(resolved_stat.st_mode & stat.S_ISVTX)
    daemon_owned_private = (
        resolved_stat.st_uid == os.geteuid() and not resolved_stat.st_mode & 0o022
    )
    if not root_owned_sticky and not daemon_owned_private:
        raise ValueError(f"{owner_label} status system temporary root is not trusted")
    return resolved, daemon_owned_private


def _open_or_create_directory_component(
    parent_descriptor: int,
    *,
    component: str,
    flags: int,
    owner_label: str,
    create: bool,
) -> int:
    try:
        return os.open(component, flags, dir_fd=parent_descriptor)
    except FileNotFoundError:
        if not create:
            raise
        with suppress(FileExistsError):
            os.mkdir(component, mode=0o700, dir_fd=parent_descriptor)
        try:
            return os.open(component, flags, dir_fd=parent_descriptor)
        except OSError as exc:
            _raise_status_parent_component_error(owner_label, exc)
    except OSError as exc:
        _raise_status_parent_component_error(owner_label, exc)


def _raise_status_parent_component_error(
    owner_label: str,
    error: OSError,
) -> NoReturn:
    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
        raise ValueError(
            f"{owner_label} status parent contains a symlink or non-directory component"
        ) from error
    raise error


def _require_safe_status_parent(
    descriptor: int,
    *,
    is_private_tmp_root: bool,
    owner_label: str,
) -> None:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{owner_label} status parent is not a directory")
    if is_private_tmp_root:
        return
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise ValueError(
            f"{owner_label} status parent must be private and owned by the daemon user"
        )


def _require_safe_status_ancestor(descriptor: int, *, owner_label: str) -> None:
    metadata = os.fstat(descriptor)
    root_owned_sticky = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
    trusted_owner = metadata.st_uid in {0, os.geteuid()}
    if not stat.S_ISDIR(metadata.st_mode) or not (
        root_owned_sticky or (trusted_owner and not metadata.st_mode & 0o022)
    ):
        raise ValueError(f"{owner_label} status parent contains an untrusted writable component")


def _create_temporary_status_file(
    parent_descriptor: int,
    *,
    destination_name: str,
    owner_label: str,
) -> tuple[int, str]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for _attempt in range(_TEMPORARY_CREATE_ATTEMPTS):
        temporary_name = f".{destination_name}.{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=parent_descriptor,
            )
        except FileExistsError:
            continue
        try:
            os.fchmod(descriptor, 0o600)
        except BaseException:
            os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            raise
        return descriptor, temporary_name
    raise FileExistsError(f"{owner_label} status temporary filename allocation was exhausted")
