"""POSIX output-root and current-directory capabilities.

The governed browser coordinator is a dedicated process.  It opens its output
root once, changes to that directory by descriptor, and keeps all live output
paths relative to that pinned current-directory inode.  A normal absolute path
is retained only as a restart/display reference.
"""

from __future__ import annotations

import os
import stat
import threading
import unicodedata
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType


class PinnedWorkspaceError(RuntimeError):
    """Raised when a pinned output-root or CWD identity is unsafe or changed."""


@dataclass(frozen=True, slots=True)
class PinnedWorkspaceIdentity:
    device: int
    inode: int
    uid: int
    mode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> PinnedWorkspaceIdentity:
        if not stat.S_ISDIR(value.st_mode) or value.st_ino <= 0:
            raise PinnedWorkspaceError("pinned workspace identity must be a directory inode")
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            uid=value.st_uid,
            mode=value.st_mode,
        )


@dataclass(frozen=True, slots=True)
class _PinnedPathLink:
    parent_fd: int
    name: str
    child_fd: int
    child_identity: PinnedWorkspaceIdentity


_ACTIVE_GUARD = threading.RLock()
_ACTIVE_IDENTITY: PinnedWorkspaceIdentity | None = None


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _require_posix_dirfd() -> None:
    if (
        os.name != "posix"
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise PinnedWorkspaceError("pinned output roots require POSIX no-follow dirfd support")


def _path_component_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _validate_component(value: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\x00" in value:
        raise ValueError("pinned output path has an invalid component")
    return value


def _reject_component_collision(parent_fd: int, requested: str) -> None:
    requested_key = _path_component_key(requested)
    for existing in os.listdir(parent_fd):
        if _path_component_key(existing) == requested_key and existing != requested:
            raise FileExistsError(
                "pinned output path collides after NFC and case-fold normalization"
            )


def _has_entry(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _reject_run_root(directory_fd: int) -> None:
    # A conservative marker-pair check is deliberate.  It rejects a malformed
    # or partially tampered Run just as it rejects a verified sealed Run, rather
    # than entering it and risking mutation before a path-based verifier runs.
    if _has_entry(directory_fd, "events.jsonl") and _has_entry(
        directory_fd, "run-integrity.jsonl"
    ):
        raise PinnedWorkspaceError("pinned output path is nested below an existing Run root")


def _open_directory_at(parent_fd: int, name: str) -> tuple[int, PinnedWorkspaceIdentity]:
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise PinnedWorkspaceError(
            "pinned output path contains a non-directory or symbolic-link component"
        ) from exc
    try:
        identity = PinnedWorkspaceIdentity.from_stat(os.fstat(descriptor))
        os.set_inheritable(descriptor, False)
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _created_private_directory_at(
    parent_fd: int,
    name: str,
) -> tuple[int, PinnedWorkspaceIdentity]:
    os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    created = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    descriptor, identity = _open_directory_at(parent_fd, name)
    try:
        if PinnedWorkspaceIdentity.from_stat(created) != identity:
            raise PinnedWorkspaceError("pinned output directory changed while it was opened")
        if os.geteuid() != identity.uid:
            raise PinnedWorkspaceError("pinned output directory is not owned by this user")
        os.fchmod(descriptor, 0o700)
        final = os.fstat(descriptor)
        final_identity = PinnedWorkspaceIdentity.from_stat(final)
        if (
            (final_identity.device, final_identity.inode) != (identity.device, identity.inode)
            or final_identity.uid != os.geteuid()
            or stat.S_IMODE(final.st_mode) != 0o700
        ):
            raise PinnedWorkspaceError("pinned output directory is not exact and private")
        os.fsync(parent_fd)
        return descriptor, final_identity
    except BaseException:
        os.close(descriptor)
        raise


class _PinnedWorkspaceActivation(AbstractContextManager[PinnedWorkspaceIdentity]):
    def __init__(
        self,
        identity: PinnedWorkspaceIdentity,
        *,
        workspace_fd: int | None,
    ) -> None:
        self._identity = identity
        self._workspace_fd = workspace_fd
        self._previous_fd: int | None = None
        self._entered = False

    def __enter__(self) -> PinnedWorkspaceIdentity:
        global _ACTIVE_IDENTITY

        with _ACTIVE_GUARD:
            if _ACTIVE_IDENTITY is not None:
                raise PinnedWorkspaceError("a pinned workspace is already active")
            self._previous_fd = os.open(".", _directory_flags())
            try:
                if self._workspace_fd is not None:
                    opened_identity = PinnedWorkspaceIdentity.from_stat(
                        os.fstat(self._workspace_fd)
                    )
                    if opened_identity != self._identity:
                        raise PinnedWorkspaceError(
                            "pinned output-root descriptor identity changed"
                        )
                    os.fchdir(self._workspace_fd)
                if PinnedWorkspaceIdentity.from_stat(os.stat(".")) != self._identity:
                    raise PinnedWorkspaceError("current directory differs from pinned workspace")
            except BaseException:
                try:
                    os.fchdir(self._previous_fd)
                finally:
                    os.close(self._previous_fd)
                    self._previous_fd = None
                raise
            _ACTIVE_IDENTITY = self._identity
            self._entered = True
        return self._identity

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        global _ACTIVE_IDENTITY

        if not self._entered:
            return
        with _ACTIVE_GUARD:
            try:
                if self._previous_fd is not None:
                    os.fchdir(self._previous_fd)
            finally:
                if self._previous_fd is not None:
                    os.close(self._previous_fd)
                self._previous_fd = None
                _ACTIVE_IDENTITY = None
                self._entered = False


class PinnedOutputRoot:
    """One newly created output root pinned by its open POSIX directory inode."""

    def __init__(
        self,
        *,
        path: Path,
        descriptors: tuple[int, ...],
        links: tuple[_PinnedPathLink, ...],
        identity: PinnedWorkspaceIdentity,
    ) -> None:
        self.path = path
        self.identity = identity
        self._descriptors = descriptors
        self._links = links
        self._root_fd = descriptors[-1]
        self._closed = False

    @classmethod
    def create(cls, path: Path) -> PinnedOutputRoot:
        """Create a new private leaf after no-follow traversal from POSIX root."""

        _require_posix_dirfd()
        if not isinstance(path, Path):
            raise TypeError("pinned output root must be a Path")
        expanded = path.expanduser()
        if ".." in expanded.parts:
            raise ValueError("pinned output root cannot contain parent traversal")
        requested = Path(os.path.abspath(os.fspath(expanded)))
        components = tuple(_validate_component(item) for item in requested.parts[1:])
        if not components:
            raise ValueError("pinned output root cannot be the filesystem root")

        descriptors: list[int] = []
        links: list[_PinnedPathLink] = []
        current = os.open(requested.anchor, _directory_flags())
        os.set_inheritable(current, False)
        descriptors.append(current)
        try:
            for index, component in enumerate(components):
                _reject_run_root(current)
                _reject_component_collision(current, component)
                final = index == len(components) - 1
                try:
                    os.stat(component, dir_fd=current, follow_symlinks=False)
                except FileNotFoundError:
                    child, identity = _created_private_directory_at(current, component)
                else:
                    if final:
                        raise FileExistsError("pinned output root already exists")
                    child, identity = _open_directory_at(current, component)
                descriptors.append(child)
                links.append(
                    _PinnedPathLink(
                        parent_fd=current,
                        name=component,
                        child_fd=child,
                        child_identity=identity,
                    )
                )
                current = child
            root_status = os.fstat(current)
            if (
                root_status.st_uid != os.geteuid()
                or stat.S_IMODE(root_status.st_mode) != 0o700
            ):
                raise PinnedWorkspaceError("pinned output root is not owner-only")
            return cls(
                path=requested,
                descriptors=tuple(descriptors),
                links=tuple(links),
                identity=PinnedWorkspaceIdentity.from_stat(root_status),
            )
        except BaseException:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            raise

    @property
    def fd(self) -> int:
        self._require_open()
        return self._root_fd

    def activate(self) -> AbstractContextManager[PinnedWorkspaceIdentity]:
        self._require_open()
        return _PinnedWorkspaceActivation(self.identity, workspace_fd=self._root_fd)

    def original_path_identity_matches(self) -> bool:
        """Check every original name-to-inode edge without reopening the caller path."""

        self._require_open()
        for link in self._links:
            try:
                child = os.stat(link.name, dir_fd=link.parent_fd, follow_symlinks=False)
                opened = os.fstat(link.child_fd)
                child_identity = PinnedWorkspaceIdentity.from_stat(child)
                opened_identity = PinnedWorkspaceIdentity.from_stat(opened)
            except (OSError, PinnedWorkspaceError):
                return False
            expected = link.child_identity
            if child_identity != expected or opened_identity != expected:
                return False
        return True

    def require_original_path_identity(self) -> None:
        if not self.original_path_identity_matches():
            raise PinnedWorkspaceError("pinned output root no longer has its original restart path")

    def close(self) -> None:
        if self._closed:
            return
        for descriptor in reversed(self._descriptors):
            os.close(descriptor)
        self._closed = True

    def __enter__(self) -> PinnedOutputRoot:
        self._require_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def _require_open(self) -> None:
        if self._closed:
            raise PinnedWorkspaceError("pinned output-root descriptor is closed")


def activate_inherited_pinned_workspace(
    identity: PinnedWorkspaceIdentity,
) -> AbstractContextManager[PinnedWorkspaceIdentity]:
    """Activate an already inherited CWD only after exact inode verification."""

    if not isinstance(identity, PinnedWorkspaceIdentity):
        raise TypeError("inherited pinned workspace identity is invalid")
    _require_posix_dirfd()
    return _PinnedWorkspaceActivation(identity, workspace_fd=None)


def active_pinned_workspace_identity() -> PinnedWorkspaceIdentity | None:
    with _ACTIVE_GUARD:
        identity = _ACTIVE_IDENTITY
        if identity is None:
            return None
        if PinnedWorkspaceIdentity.from_stat(os.stat(".")) != identity:
            raise PinnedWorkspaceError(
                "current directory changed while pinned workspace was active"
            )
        return identity


def pinned_workspace_relative_path(path: Path, *, label: str) -> Path | None:
    """Return a validated relative path only while a pinned CWD is active."""

    if active_pinned_workspace_identity() is None:
        return None
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"{label} must stay below the pinned workspace")
    for component in candidate.parts:
        _validate_component(component)
    return candidate


__all__ = [
    "PinnedOutputRoot",
    "PinnedWorkspaceError",
    "PinnedWorkspaceIdentity",
    "activate_inherited_pinned_workspace",
    "active_pinned_workspace_identity",
    "pinned_workspace_relative_path",
]
