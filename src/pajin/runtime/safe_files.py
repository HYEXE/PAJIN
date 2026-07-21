"""Small symlink-safe atomic writer for standalone generated artifacts."""

from __future__ import annotations

import errno
import json
import math
import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path
from typing import NoReturn

_TEMPORARY_CREATE_ATTEMPTS = 16
_READ_CHUNK_BYTES = 1024 * 1024
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIRECTORY_MODE = 0o700
_DEFAULT_MAX_STRICT_JSON_BYTES = 64 * 1024 * 1024
_DEFAULT_MAX_STRICT_JSON_DEPTH = 64
_DEFAULT_MAX_STRICT_JSON_NODES = 200_000


def read_bounded_regular_bytes(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    require_single_link: bool = False,
) -> bytes:
    """Read one bounded regular file without following path components.

    The descriptor, leaf entry, size, and revision are rebound after the read.
    Callers must still choose a limit appropriate for the artifact contract.
    """

    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    source = _absolute_path(path)
    if not source.name or source.name in {".", ".."}:
        raise ValueError(f"{label} path requires a filename")
    if _posix_read_dirfd_available():
        return _read_bounded_posix(
            source,
            max_bytes=max_bytes,
            label=label,
            require_single_link=require_single_link,
        )
    return _read_bounded_portable(
        source,
        max_bytes=max_bytes,
        label=label,
        require_single_link=require_single_link,
    )


def parse_strict_json_bytes(
    content: bytes,
    *,
    label: str,
    max_bytes: int = _DEFAULT_MAX_STRICT_JSON_BYTES,
    max_depth: int = _DEFAULT_MAX_STRICT_JSON_DEPTH,
    max_nodes: int = _DEFAULT_MAX_STRICT_JSON_NODES,
) -> object:
    """Parse resource-bounded UTF-8 JSON without last-wins ambiguity."""

    if not isinstance(content, bytes):
        raise TypeError(f"{label} content must be bytes")
    _validate_json_limits(max_bytes=max_bytes, max_depth=max_depth, max_nodes=max_nodes)
    if len(content) > max_bytes:
        raise ValueError(f"{label} exceeds the {max_bytes}-byte limit")
    try:
        text = content.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{label} is not strict JSON") from exc
    _preflight_json_structure(
        text,
        label=label,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant is forbidden: {value}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("non-finite JSON number is forbidden")
        return parsed

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError(f"{label} is not strict JSON") from exc
    _validate_decoded_json(
        decoded,
        label=label,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    return decoded


def load_bounded_strict_json(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    require_single_link: bool = False,
    max_depth: int = _DEFAULT_MAX_STRICT_JSON_DEPTH,
    max_nodes: int = _DEFAULT_MAX_STRICT_JSON_NODES,
) -> object:
    """Read and parse one bounded, no-follow strict JSON file."""

    return parse_strict_json_bytes(
        read_bounded_regular_bytes(
            path,
            max_bytes=max_bytes,
            label=label,
            require_single_link=require_single_link,
        ),
        label=label,
        max_bytes=max_bytes,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )


def _validate_json_limits(*, max_bytes: int, max_depth: int, max_nodes: int) -> None:
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    if type(max_depth) is not int or max_depth < 0:
        raise ValueError("max_depth must be a non-negative integer")
    if type(max_nodes) is not int or max_nodes < 1:
        raise ValueError("max_nodes must be a positive integer")


def _preflight_json_structure(
    text: str,
    *,
    label: str,
    max_depth: int,
    max_nodes: int,
) -> None:
    """Bound nesting and token width before the allocating stdlib decoder runs."""

    stack: list[str] = []
    tokens = 0
    index = 0
    while index < len(text):
        character = text[index]
        if character.isspace() or character in {",", ":"}:
            index += 1
            continue
        if character == '"':
            index += 1
            closed = False
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    index += 1
                    closed = True
                    break
                index += 1
            if not closed:
                raise ValueError(f"{label} is not strict JSON")
            tokens += 1
        elif character in {"{", "["}:
            if len(stack) > max_depth:
                raise ValueError(f"{label} exceeds the JSON nesting-depth limit")
            stack.append(character)
            tokens += 1
            index += 1
        elif character in {"}", "]"}:
            expected = "{" if character == "}" else "["
            if not stack or stack.pop() != expected:
                raise ValueError(f"{label} is not strict JSON")
            index += 1
            continue
        else:
            while index < len(text) and not (text[index].isspace() or text[index] in "{}[],:"):
                index += 1
            tokens += 1
        if tokens > max_nodes:
            raise ValueError(f"{label} exceeds the JSON node-count limit")
    if stack:
        raise ValueError(f"{label} is not strict JSON")


def _validate_decoded_json(
    decoded: object,
    *,
    label: str,
    max_depth: int,
    max_nodes: int,
) -> None:
    stack: list[tuple[object, int]] = [(decoded, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ValueError(f"{label} exceeds the JSON node-count limit")
        if depth > max_depth:
            raise ValueError(f"{label} exceeds the JSON nesting-depth limit")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
        elif (
            value is None
            or isinstance(value, (str, bool, int))
            or (isinstance(value, float) and math.isfinite(value))
        ):
            continue
        else:  # pragma: no cover - stdlib JSON decoder shape invariant
            raise ValueError(f"{label} contains a non-JSON value")


def atomic_write_text_no_follow(path: Path, content: str, *, label: str) -> None:
    """Atomically replace a regular text file without following parent or leaf links.

    Existing regular files remain replaceable. Symbolic links, junctions, directories, and
    special-file leaves fail closed. POSIX writes stay anchored to an opened parent directory;
    the portable fallback revalidates every lexical parent component and its identity.
    """

    if not isinstance(content, str):
        raise TypeError(f"{label} content must be text")
    destination = _absolute_path(path)
    if not destination.name or destination.name in {".", ".."}:
        raise ValueError(f"{label} path requires a filename")
    payload = content.encode("utf-8")
    if _posix_dirfd_available():
        _atomic_write_posix(destination, payload, label=label)
        return
    _atomic_write_portable(destination, payload, label=label)


def _absolute_path(path: Path) -> Path:
    """Normalize lexical components without resolving any symbolic links."""

    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _posix_dirfd_available() -> bool:
    required = (os.open, os.mkdir, os.rename, os.unlink)
    return bool(
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and all(operation in os.supports_dir_fd for operation in required)
    )


def _posix_read_dirfd_available() -> bool:
    return bool(
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
    )


def _read_bounded_posix(
    source: Path,
    *,
    max_bytes: int,
    label: str,
    require_single_link: bool,
) -> bytes:
    parent_descriptor = _open_existing_posix_parent(source.parent, label=label)
    descriptor = -1
    try:
        try:
            observed = os.stat(
                source.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ValueError(f"{label} path cannot be inspected safely") from exc
        _require_readable_regular_metadata(
            observed,
            max_bytes=max_bytes,
            label=label,
            require_single_link=require_single_link,
        )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            descriptor = os.open(source.name, flags, dir_fd=parent_descriptor)
        except OSError as exc:
            raise ValueError(f"{label} path cannot be opened safely") from exc
        opened = os.fstat(descriptor)
        _require_same_regular_file(
            observed,
            opened,
            max_bytes=max_bytes,
            label=label,
            require_single_link=require_single_link,
        )
        content = _read_bounded_descriptor(
            descriptor,
            opened,
            max_bytes=max_bytes,
            label=label,
        )
        final_path = os.stat(
            source.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _require_same_revision(opened, final_path, label=label)
        return content
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _open_existing_posix_parent(parent: Path, *, label: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    descriptor = os.open(parent.anchor, flags)
    try:
        for component in parent.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                _raise_parent_error(label, exc)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_bounded_portable(
    source: Path,
    *,
    max_bytes: int,
    label: str,
    require_single_link: bool,
) -> bytes:
    parent_identity = _require_existing_portable_parent(source.parent, label=label)
    try:
        observed = source.lstat()
    except OSError as exc:
        raise ValueError(f"{label} path cannot be inspected safely") from exc
    if _is_link_or_junction(source):
        raise ValueError(f"{label} path must not be a symbolic link")
    _require_readable_regular_metadata(
        observed,
        max_bytes=max_bytes,
        label=label,
        require_single_link=require_single_link,
    )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(source, flags)
    try:
        opened = os.fstat(descriptor)
        _require_same_regular_file(
            observed,
            opened,
            max_bytes=max_bytes,
            label=label,
            require_single_link=require_single_link,
        )
        content = _read_bounded_descriptor(
            descriptor,
            opened,
            max_bytes=max_bytes,
            label=label,
        )
        _require_portable_parent_identity(source.parent, parent_identity, label=label)
        final_path = source.lstat()
        if _is_link_or_junction(source):
            raise ValueError(f"{label} path changed while being read")
        _require_same_revision(opened, final_path, label=label)
        return content
    finally:
        os.close(descriptor)


def _require_existing_portable_parent(parent: Path, *, label: str) -> tuple[int, int]:
    current = Path(parent.anchor)
    for component in parent.parts[1:]:
        current /= component
        _require_portable_directory(current, label=label)
    return _portable_identity(parent, label=label)


def _require_readable_regular_metadata(
    metadata: os.stat_result,
    *,
    max_bytes: int,
    label: str,
    require_single_link: bool,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} path must be a regular file")
    if require_single_link and metadata.st_nlink != 1:
        raise ValueError(f"{label} path must have exactly one hard link")
    if metadata.st_size > max_bytes:
        raise ValueError(f"{label} exceeds the {max_bytes}-byte limit")


def _require_same_regular_file(
    observed: os.stat_result,
    opened: os.stat_result,
    *,
    max_bytes: int,
    label: str,
    require_single_link: bool,
) -> None:
    _require_readable_regular_metadata(
        opened,
        max_bytes=max_bytes,
        label=label,
        require_single_link=require_single_link,
    )
    if (observed.st_dev, observed.st_ino) != (opened.st_dev, opened.st_ino):
        raise ValueError(f"{label} path changed while being opened")


def _read_bounded_descriptor(
    descriptor: int,
    opened: os.stat_result,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    chunks: list[bytes] = []
    observed_bytes = 0
    while True:
        chunk = os.read(
            descriptor,
            min(_READ_CHUNK_BYTES, max_bytes + 1 - observed_bytes),
        )
        if not chunk:
            break
        chunks.append(chunk)
        observed_bytes += len(chunk)
        if observed_bytes > max_bytes:
            raise ValueError(f"{label} exceeds the {max_bytes}-byte limit")
    final_descriptor = os.fstat(descriptor)
    _require_same_revision(opened, final_descriptor, label=label)
    if observed_bytes != opened.st_size:
        raise ValueError(f"{label} changed while being read")
    return b"".join(chunks)


def _require_same_revision(
    expected: os.stat_result,
    observed: os.stat_result,
    *,
    label: str,
) -> None:
    if not stat.S_ISREG(observed.st_mode) or (
        observed.st_dev,
        observed.st_ino,
        observed.st_size,
        observed.st_mtime_ns,
        observed.st_ctime_ns,
    ) != (
        expected.st_dev,
        expected.st_ino,
        expected.st_size,
        expected.st_mtime_ns,
        expected.st_ctime_ns,
    ):
        raise ValueError(f"{label} changed while being read")


def _atomic_write_posix(destination: Path, payload: bytes, *, label: str) -> None:
    parent_descriptor = _open_posix_parent(destination.parent, label=label)
    descriptor = -1
    temporary_name: str | None = None
    try:
        _require_replaceable_posix_leaf(
            parent_descriptor,
            destination.name,
            label=label,
        )
        descriptor, temporary_name = _create_posix_temporary(
            parent_descriptor,
            destination_name=destination.name,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _require_replaceable_posix_leaf(
            parent_descriptor,
            destination.name,
            label=label,
        )
        os.replace(
            temporary_name,
            destination.name,
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


def _open_posix_parent(parent: Path, *, label: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    descriptor = os.open(parent.anchor, flags)
    try:
        for component in parent.parts[1:]:
            child = _open_or_create_posix_directory(
                descriptor,
                component,
                flags=flags,
                label=label,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_or_create_posix_directory(
    parent_descriptor: int,
    component: str,
    *,
    flags: int,
    label: str,
) -> int:
    try:
        return os.open(component, flags, dir_fd=parent_descriptor)
    except FileNotFoundError:
        with suppress(FileExistsError):
            os.mkdir(
                component,
                mode=_PRIVATE_DIRECTORY_MODE,
                dir_fd=parent_descriptor,
            )
        try:
            return os.open(component, flags, dir_fd=parent_descriptor)
        except OSError as exc:
            _raise_parent_error(label, exc)
    except OSError as exc:
        _raise_parent_error(label, exc)


def _raise_parent_error(label: str, error: OSError) -> NoReturn:
    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
        raise ValueError(
            f"{label} parent contains a symbolic link or non-directory component"
        ) from error
    raise error


def _require_replaceable_posix_leaf(
    parent_descriptor: int,
    name: str,
    *,
    label: str,
) -> None:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"{label} path must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} path must be a regular file")


def _create_posix_temporary(
    parent_descriptor: int,
    *,
    destination_name: str,
) -> tuple[int, str]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    for _attempt in range(_TEMPORARY_CREATE_ATTEMPTS):
        name = f".{destination_name}.{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(
                name,
                flags,
                _PRIVATE_FILE_MODE,
                dir_fd=parent_descriptor,
            )
        except FileExistsError:
            continue
        try:
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        except BaseException:
            os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(name, dir_fd=parent_descriptor)
            raise
        return descriptor, name
    raise FileExistsError("secure temporary filename allocation was exhausted")


def _atomic_write_portable(destination: Path, payload: bytes, *, label: str) -> None:
    parent_identity = _prepare_portable_parent(destination.parent, label=label)
    _require_replaceable_portable_leaf(destination, label=label)
    temporary = destination.parent / f".{destination.name}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0),
            _PRIVATE_FILE_MODE,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _require_portable_parent_identity(destination.parent, parent_identity, label=label)
        _require_replaceable_portable_leaf(destination, label=label)
        os.replace(temporary, destination)
        _require_portable_parent_identity(destination.parent, parent_identity, label=label)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()


def _prepare_portable_parent(parent: Path, *, label: str) -> tuple[int, int]:
    current = Path(parent.anchor)
    for component in parent.parts[1:]:
        current /= component
        with suppress(FileExistsError):
            current.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
        _require_portable_directory(current, label=label)
    return _portable_identity(parent, label=label)


def _require_portable_directory(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} parent changed while being prepared") from exc
    if _is_link_or_junction(path) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} parent contains a symbolic link or non-directory component")


def _portable_identity(path: Path, *, label: str) -> tuple[int, int]:
    _require_portable_directory(path, label=label)
    metadata = path.lstat()
    return metadata.st_dev, metadata.st_ino


def _require_portable_parent_identity(
    path: Path,
    expected: tuple[int, int],
    *,
    label: str,
) -> None:
    if _portable_identity(path, label=label) != expected:
        raise ValueError(f"{label} parent changed during atomic replacement")


def _require_replaceable_portable_leaf(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if _is_link_or_junction(path):
        raise ValueError(f"{label} path must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} path must be a regular file")


def _is_link_or_junction(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()
