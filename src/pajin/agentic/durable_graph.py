"""Durable Canonical Graph head resolution for agentic planning.

Caller-authored Graph objects are inert inputs.  Only this resolver can turn an
exact Snapshot reference into an opaque handle, and every planning read checks
that handle against the same physical SQLite store and its current verified
head again.  The verification read is not an atomic lock over later planning or
model work; downstream durable checkpoint CAS must still reject a head change.
"""

from __future__ import annotations

import os
import stat
from _thread import RLock as RLockType
from contextlib import suppress
from pathlib import Path
from re import fullmatch
from threading import RLock
from typing import NoReturn, cast, final

from pydantic import ValidationError

from pajin.graph.projection import (
    GraphProjectionError,
    GraphSnapshot,
    GraphSnapshotRef,
    graph_snapshot_ref,
)
from pajin.graph.sqlite_store import (
    SQLiteGraphStore,
    SQLiteGraphStoreError,
    load_verified_current_graph_snapshot_from_descriptor,
)

_StoreIdentity = tuple[tuple[int, int], tuple[int, int]]
_StoreState = tuple[_StoreIdentity, int, int, int]


class AgenticGraphHeadError(RuntimeError):
    """Raised when an exact current durable Graph head cannot be proven."""


@final
class VerifiedCurrentGraphHead:
    """Opaque resolver-bound handle for one exact verified current Graph head.

    The handle intentionally exposes only a defensive ``GraphSnapshotRef``.
    The complete Snapshot is available solely through the resolver that issued
    the handle, which revalidates durable current-head authority at consumption.
    """

    __slots__ = ("_reference", "_resolver_token", "_store_identity")

    _reference: GraphSnapshotRef
    _resolver_token: object
    _store_identity: _StoreIdentity

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedCurrentGraphHead:
        raise TypeError(
            "VerifiedCurrentGraphHead is opaque; use CurrentGraphHeadResolver.resolve()"
        )

    def __init_subclass__(cls) -> None:
        raise TypeError("VerifiedCurrentGraphHead cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise AttributeError("VerifiedCurrentGraphHead is immutable")

    def __delattr__(self, _name: str) -> NoReturn:
        raise AttributeError("VerifiedCurrentGraphHead is immutable")

    @property
    def reference(self) -> GraphSnapshotRef:
        """Return a defensive exact reference, never the authoritative Snapshot."""

        reference = object.__getattribute__(self, "_reference")
        return GraphSnapshotRef.model_validate(reference.model_dump(mode="json", by_alias=True))

    @property
    def campaign_id(self) -> str:
        reference = cast(
            GraphSnapshotRef,
            object.__getattribute__(self, "_reference"),
        )
        return reference.campaign_id

    @property
    def snapshot_id(self) -> str:
        reference = cast(
            GraphSnapshotRef,
            object.__getattribute__(self, "_reference"),
        )
        return reference.snapshot_id

    @property
    def snapshot_digest(self) -> str:
        reference = cast(
            GraphSnapshotRef,
            object.__getattribute__(self, "_reference"),
        )
        return reference.snapshot_digest


@final
class CurrentGraphHeadResolver:
    """Read-only authority seam from a durable Graph Store into agentic planning."""

    __slots__ = (
        "__campaign_id",
        "__closed",
        "__database_descriptor",
        "__graph_database",
        "__parent_descriptor",
        "__resolver_token",
        "__store_identity",
        "_lock",
    )

    __campaign_id: str
    __closed: bool
    __database_descriptor: int
    __graph_database: Path
    __parent_descriptor: int
    __resolver_token: object
    __store_identity: _StoreIdentity
    _lock: RLockType

    def __init__(self, graph_database: Path, *, campaign_id: str) -> None:
        if os.name != "posix":
            raise AgenticGraphHeadError(
                "durable Graph head resolution requires POSIX descriptor pinning"
            )
        if not isinstance(graph_database, Path):
            raise TypeError("Agentic Graph database must be a pathlib.Path")
        if (
            type(campaign_id) is not str
            or fullmatch(r"^[a-z0-9][a-z0-9-]{2,79}$", campaign_id) is None
        ):
            raise ValueError("Agentic Graph Campaign ID is invalid")
        database = Path(os.path.abspath(os.fspath(graph_database.expanduser())))
        initial_state = _store_state(database)
        parent_descriptor = os.open(
            database.parent,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            parent_stat = os.fstat(parent_descriptor)
            parent_identity = (parent_stat.st_dev, parent_stat.st_ino)
            if parent_identity != initial_state[0][0]:
                raise AgenticGraphHeadError(
                    "durable Graph Store parent changed while its descriptor was pinned"
                )
            descriptor = os.open(
                database.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_descriptor,
            )
        except BaseException:
            os.close(parent_descriptor)
            raise
        try:
            descriptor_stat = os.fstat(descriptor)
            descriptor_identity = (descriptor_stat.st_dev, descriptor_stat.st_ino)
            if descriptor_identity != initial_state[0][1]:
                raise AgenticGraphHeadError(
                    "durable Graph Store changed while its descriptor was pinned"
                )
            if _store_state(database) != initial_state:
                raise AgenticGraphHeadError(
                    "durable Graph Store changed while its descriptor was pinned"
                )
            os.set_inheritable(descriptor, False)
            os.set_inheritable(parent_descriptor, False)
        except BaseException:
            os.close(descriptor)
            os.close(parent_descriptor)
            raise
        object.__setattr__(self, "_CurrentGraphHeadResolver__graph_database", database)
        object.__setattr__(self, "_CurrentGraphHeadResolver__campaign_id", campaign_id)
        object.__setattr__(self, "_CurrentGraphHeadResolver__closed", False)
        object.__setattr__(
            self,
            "_CurrentGraphHeadResolver__database_descriptor",
            descriptor,
        )
        object.__setattr__(
            self,
            "_CurrentGraphHeadResolver__parent_descriptor",
            parent_descriptor,
        )
        object.__setattr__(self, "_CurrentGraphHeadResolver__resolver_token", object())
        object.__setattr__(
            self,
            "_CurrentGraphHeadResolver__store_identity",
            initial_state[0],
        )
        object.__setattr__(self, "_lock", RLock())

    def __init_subclass__(cls) -> None:
        raise TypeError("CurrentGraphHeadResolver cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise AttributeError("CurrentGraphHeadResolver deployment binding is immutable")

    def __delattr__(self, _name: str) -> NoReturn:
        raise AttributeError("CurrentGraphHeadResolver deployment binding is immutable")

    def __enter__(self) -> CurrentGraphHeadResolver:
        self._require_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            descriptor = object.__getattribute__(
                self,
                "_CurrentGraphHeadResolver__database_descriptor",
            )
            parent_descriptor = object.__getattribute__(
                self,
                "_CurrentGraphHeadResolver__parent_descriptor",
            )
            closed = object.__getattribute__(
                self,
                "_CurrentGraphHeadResolver__closed",
            )
        except AttributeError:
            return
        if not closed:
            with suppress(OSError):
                os.close(descriptor)
            with suppress(OSError):
                os.close(parent_descriptor)

    def close(self) -> None:
        """Release this resolver's pinned database descriptor."""

        with self._lock:
            if not self.__closed:
                error: OSError | None = None
                for descriptor in (
                    self.__database_descriptor,
                    self.__parent_descriptor,
                ):
                    try:
                        os.close(descriptor)
                    except OSError as exc:
                        error = error or exc
                object.__setattr__(
                    self,
                    "_CurrentGraphHeadResolver__closed",
                    True,
                )
                if error is not None:
                    raise error

    def resolve(self, reference: GraphSnapshotRef) -> VerifiedCurrentGraphHead:
        """Resolve one exact caller reference against the independently verified head."""

        self._require_open()
        canonical = _canonical_reference(reference)
        self._require_campaign(canonical)
        with self._lock:
            self._require_open()
            snapshot, store_identity = self._load_exact_current(canonical)
            resolved_reference = graph_snapshot_ref(snapshot)
            return _new_verified_current_graph_head(
                resolver_token=self.__resolver_token,
                store_identity=store_identity,
                reference=resolved_reference,
            )

    def snapshot_for_planning(self, handle: VerifiedCurrentGraphHead) -> GraphSnapshot:
        """Revalidate one issued handle and return a defensive planning Snapshot.

        Handle validation happens before any durable read.  Consequently a raw
        ``GraphSnapshot``, a forged object, or a handle from another resolver
        cannot trigger downstream model work through this seam.
        """

        with self._lock:
            self._require_open()
            reference = self._require_issued_handle(handle)
            snapshot, _store_identity = self._load_exact_current(reference)
            return GraphSnapshot.model_validate(snapshot.model_dump(mode="json", by_alias=True))

    def require_runtime_store(
        self,
        store: SQLiteGraphStore,
        handle: VerifiedCurrentGraphHead,
    ) -> None:
        """Bind a mutable runtime Store to this resolver's pinned physical database.

        Planning normally needs only a read-only descriptor.  A Permit runtime,
        however, also needs the concrete Graph Store that owns the approval and
        Permit writer.  This check prevents a same-shaped Store for another file
        from being substituted after the current-head handle was resolved.
        """

        if type(store) is not SQLiteGraphStore:
            raise AgenticGraphHeadError(
                "durable Graph runtime requires the exact SQLite Graph Store"
            )
        with self._lock:
            self._require_open()
            reference = self._require_issued_handle(handle)
            if (
                store.campaign_id != self.__campaign_id
                or Path(os.path.abspath(os.fspath(store.path))) != self.__graph_database
                or store.runtime_file_identity() != self.__store_identity
            ):
                raise AgenticGraphHeadError(
                    "durable Graph runtime Store differs from the pinned resolver"
                )
            self._load_exact_current(reference)

    def _require_issued_handle(
        self,
        handle: VerifiedCurrentGraphHead,
    ) -> GraphSnapshotRef:
        if type(handle) is not VerifiedCurrentGraphHead:
            raise TypeError("agentic planning requires an exact verified Graph head handle")
        try:
            resolver_token = object.__getattribute__(handle, "_resolver_token")
            store_identity = object.__getattribute__(handle, "_store_identity")
            reference = object.__getattribute__(handle, "_reference")
        except AttributeError as exc:
            raise AgenticGraphHeadError("verified Graph head handle is incomplete") from exc
        if resolver_token is not self.__resolver_token:
            raise AgenticGraphHeadError("verified Graph head handle belongs to another resolver")
        if type(store_identity) is not tuple or store_identity != self.__store_identity:
            raise AgenticGraphHeadError(
                "verified Graph head handle belongs to another durable store"
            )
        canonical = _canonical_reference(reference)
        self._require_campaign(canonical)
        return canonical

    def _require_campaign(self, reference: GraphSnapshotRef) -> None:
        if reference.campaign_id != self.__campaign_id:
            raise AgenticGraphHeadError(
                "Graph Snapshot reference belongs to another deployment Campaign"
            )

    def _require_open(self) -> None:
        if self.__closed:
            raise AgenticGraphHeadError("current Graph head resolver is closed")

    def _load_exact_current(
        self,
        reference: GraphSnapshotRef,
    ) -> tuple[GraphSnapshot, _StoreIdentity]:
        try:
            before = _store_state(self.__graph_database)
            if before[0] != self.__store_identity:
                raise AgenticGraphHeadError(
                    "durable Graph Store identity changed after resolver binding"
                )
            snapshot = load_verified_current_graph_snapshot_from_descriptor(
                self.__database_descriptor,
                parent_descriptor=self.__parent_descriptor,
                database_name=self.__graph_database.name,
                campaign_id=self.__campaign_id,
                snapshot_id=reference.snapshot_id,
            )
            after = _store_state(self.__graph_database)
            if after != before:
                raise AgenticGraphHeadError(
                    "durable Graph Store changed during agentic head resolution"
                )
            if snapshot is None:
                raise AgenticGraphHeadError(
                    "referenced Graph Snapshot is not the current durable head"
                )
            resolved_reference = graph_snapshot_ref(snapshot)
            if _reference_wire(resolved_reference) != _reference_wire(reference):
                raise AgenticGraphHeadError(
                    "resolved Graph head differs from the exact requested reference"
                )
            if self.__store_identity != before[0]:
                raise AgenticGraphHeadError(
                    "durable Graph Store identity changed after resolver binding"
                )
            return snapshot, before[0]
        except AgenticGraphHeadError:
            raise
        except (
            FileNotFoundError,
            OSError,
            GraphProjectionError,
            SQLiteGraphStoreError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgenticGraphHeadError("current durable Graph head verification failed") from exc


def _canonical_reference(reference: GraphSnapshotRef) -> GraphSnapshotRef:
    if type(reference) is not GraphSnapshotRef:
        raise TypeError("agentic Graph head resolution requires an exact GraphSnapshotRef")
    try:
        canonical = GraphSnapshotRef.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise AgenticGraphHeadError("Graph Snapshot reference is not canonical") from exc
    if _reference_wire(canonical) != _reference_wire(reference):
        raise AgenticGraphHeadError("Graph Snapshot reference differs from its canonical wire")
    return canonical


def _reference_wire(reference: GraphSnapshotRef) -> dict[str, object]:
    return reference.model_dump(mode="json", by_alias=True)


def _store_state(path: Path) -> _StoreState:
    _require_plain_directory_components(path.parent)
    parent = path.parent.lstat()
    database = path.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or not stat.S_ISREG(database.st_mode)
        or database.st_nlink != 1
    ):
        raise AgenticGraphHeadError(
            "durable Graph Store path identity is not a private regular file"
        )
    if os.name == "posix":
        if parent.st_uid != os.geteuid() or database.st_uid != os.geteuid():
            raise AgenticGraphHeadError(
                "durable Graph Store and its parent must be owned by this user"
            )
        if stat.S_IMODE(parent.st_mode) & 0o077 or stat.S_IMODE(database.st_mode) & 0o077:
            raise AgenticGraphHeadError("durable Graph Store and its parent must be owner-only")
    identity: _StoreIdentity = (
        (parent.st_dev, parent.st_ino),
        (database.st_dev, database.st_ino),
    )
    return (
        identity,
        database.st_size,
        database.st_mtime_ns,
        database.st_ctime_ns,
    )


def _require_plain_directory_components(directory: Path) -> None:
    current = Path(directory.anchor)
    components = directory.parts[1:] if directory.is_absolute() else directory.parts
    for component in components:
        current /= component
        component_stat = current.lstat()
        is_junction = getattr(current, "is_junction", lambda: False)()
        if current.is_symlink() or is_junction or not stat.S_ISDIR(component_stat.st_mode):
            raise AgenticGraphHeadError(
                "durable Graph Store path contains a symbolic-link or non-directory component"
            )


def _new_verified_current_graph_head(
    *,
    resolver_token: object,
    store_identity: _StoreIdentity,
    reference: GraphSnapshotRef,
) -> VerifiedCurrentGraphHead:
    handle = object.__new__(VerifiedCurrentGraphHead)
    object.__setattr__(handle, "_resolver_token", resolver_token)
    object.__setattr__(handle, "_store_identity", store_identity)
    object.__setattr__(handle, "_reference", _canonical_reference(reference))
    return handle


__all__ = [
    "AgenticGraphHeadError",
    "CurrentGraphHeadResolver",
    "VerifiedCurrentGraphHead",
]
