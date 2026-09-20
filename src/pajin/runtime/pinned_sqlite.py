"""Path-independent SQLite execution with descriptor-relative final publication.

This module is deliberately narrow.  It supports governed, non-resumable local
executions which need SQLite's transactional semantics in process but must not
let SQLite reopen an attacker-swappable pathname.  The live database therefore
uses a shared in-memory URI.  Once frozen, its exact serialized bytes are
published below a directory pinned by file descriptor; the published database
is evidence only and is never reopened for writing by the execution process.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import threading
import unicodedata
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Final, NoReturn, SupportsIndex, cast, final

from pajin.runtime.pinned_workspace import (
    PinnedWorkspaceIdentity,
    active_pinned_workspace_identity,
    pinned_workspace_relative_path,
)
from pajin.runtime.safe_files import parse_strict_json_bytes

if TYPE_CHECKING:
    from pajin.web_assessment.governed_campaign_evidence import (
        GovernedWebCampaignParentWriter,
    )


class PinnedSQLiteError(RuntimeError):
    """Raised when a governed in-memory SQLite authority loses its exact scope."""


_STORE_KIND_PATTERN: Final = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_CAMPAIGN_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9-]{2,79}$")
_RUN_ID_PATTERN: Final = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
_SHA256_PATTERN: Final = re.compile(r"^[a-f0-9]{64}$")
_REGISTRY_LOCK = threading.RLock()
_FRESH_AUTHORITY_FACTORY_TOKEN = object()
_GOVERNED_DATABASE_NAMES: Final = {
    "governed-web-graph": "governed-web.sqlite3",
    "governed-web-grant": "capability-grant-consumptions.sqlite3",
}
_ENROLLMENT_API_VERSION: Final = "pajin.dev/pinned-sqlite-enrollment/v1alpha1"
_ENROLLMENT_KIND: Final = "PinnedSQLiteEnrollment"
_ENROLLMENT_DIGEST_DOMAIN: Final = b"pajin.pinned-sqlite-enrollment/v1\0"
_ENROLLMENT_NAME_PREFIX: Final = ".pajin-governed-sqlite-enrollment-v1-"


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _regular_read_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )


def _regular_write_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )


def _component_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def is_governed_pinned_sqlite_namespace(path: Path, *, store_kind: str) -> bool:
    """Return whether an exact DB inode namespace was enrolled as governed.

    The canonical basename alone is intentionally insufficient: ordinary Graph
    and Grant stores may legitimately use the same directory and filename.
    Governed creation publishes a create-only enrollment beside the database,
    and an active in-memory registration additionally follows the pinned parent
    inode if that directory is renamed.
    """

    if not isinstance(path, Path):
        raise TypeError("governed SQLite namespace path must be a Path")
    expected_leaf = _GOVERNED_DATABASE_NAMES.get(store_kind)
    if expected_leaf is None:
        raise ValueError("governed SQLite namespace store kind is invalid")
    normalized = Path(os.path.abspath(path))
    if _component_key(normalized.name) != _component_key(expected_leaf):
        return False
    relative = f"{normalized.parent.name}/{normalized.name}"
    path_digest = _enrollment_path_digest(store_kind=store_kind, path=relative)
    try:
        root_fd = os.open(normalized.parent.parent, _directory_flags())
    except OSError:
        return False
    try:
        names = tuple(os.listdir(root_fd))
        prefix = f"{_ENROLLMENT_NAME_PREFIX}{store_kind}-"
        if any(
            _component_key(name).startswith(_component_key(prefix))
            and f"-{path_digest}-" in name
            for name in names
        ):
            return True
        try:
            parent_fd = os.open(normalized.parent, _directory_flags())
        except OSError:
            # In an output root that already has a governed enrollment, an
            # unsafe alias to the canonical leaf is ambiguous and cannot be
            # opened for writing.
            return any(
                _component_key(name).startswith(_component_key(prefix)) for name in names
            )
        try:
            parent_identity = _identity(os.fstat(parent_fd))
            parent_digest = _enrollment_parent_digest(
                store_kind=store_kind,
                leaf=expected_leaf,
                parent_identity=parent_identity,
            )
            if any(
                _component_key(name).startswith(_component_key(prefix))
                and name.endswith(f"-{parent_digest}.json")
                for name in names
            ):
                return True
            with _REGISTRY_LOCK:
                return any(
                    database.store_kind == store_kind
                    and _component_key(database.path.name) == _component_key(expected_leaf)
                    and database._parent.identity == parent_identity
                    for database in _DATABASES.values()
                )
        finally:
            os.close(parent_fd)
    finally:
        os.close(root_fd)


def _enrollment_path_digest(*, store_kind: str, path: str) -> str:
    return sha256(f"{store_kind}\0{path}".encode()).hexdigest()


def _enrollment_parent_digest(
    *,
    store_kind: str,
    leaf: str,
    parent_identity: PinnedWorkspaceIdentity,
) -> str:
    return sha256(
        (
            f"{store_kind}\0{leaf}\0{parent_identity.device}\0"
            f"{parent_identity.inode}\0{parent_identity.uid}"
        ).encode()
    ).hexdigest()


def _governed_enrollment_name(
    *,
    path: str,
    store_kind: str,
    leaf: str,
    parent_identity: PinnedWorkspaceIdentity,
) -> str:
    path_digest = _enrollment_path_digest(store_kind=store_kind, path=path)
    parent_digest = _enrollment_parent_digest(
        store_kind=store_kind,
        leaf=leaf,
        parent_identity=parent_identity,
    )
    return (
        f"{_ENROLLMENT_NAME_PREFIX}{store_kind}-"
        f"{path_digest}-{parent_digest}.json"
    )


def _validate_component(value: str, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\x00" in value
    ):
        raise ValueError(f"{label} has an invalid path component")
    return value


def _require_component_available(parent_fd: int, requested: str) -> None:
    requested_key = _component_key(requested)
    for existing in os.listdir(parent_fd):
        if _component_key(existing) == requested_key and existing != requested:
            raise FileExistsError(
                "pinned SQLite path collides after NFC and case-fold normalization"
            )


def _canonical_json(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError) as exc:
        raise PinnedSQLiteError("pinned SQLite checkpoint metadata is not canonical JSON") from exc
    try:
        if json.loads(encoded) != value:
            raise PinnedSQLiteError("pinned SQLite checkpoint metadata changes in JSON")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PinnedSQLiteError("pinned SQLite checkpoint metadata is invalid") from exc
    return encoded


def _identity(value: os.stat_result) -> PinnedWorkspaceIdentity:
    try:
        return PinnedWorkspaceIdentity.from_stat(value)
    except (ValueError, RuntimeError) as exc:
        raise PinnedSQLiteError("pinned SQLite directory identity is invalid") from exc


@dataclass(frozen=True, slots=True)
class PinnedSQLitePublication:
    reference: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class PinnedSQLiteCheckpoint:
    ordinal: int
    database_reference: str
    database_sha256: str
    database_size: int
    manifest_reference: str
    manifest_digest: str
    manifest_sha256: str
    manifest_size: int
    previous_manifest_digest: str | None
    state_json: bytes

    @property
    def state_digest(self) -> str:
        return sha256(self.state_json).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifiedPinnedSQLiteDatabase:
    """Read-only proof of one exact final database and its complete checkpoint chain."""

    final_publication: PinnedSQLitePublication
    enrollment_publication: PinnedSQLitePublication
    checkpoints: tuple[PinnedSQLiteCheckpoint, ...]
    database_bytes: bytes

    @property
    def latest_checkpoint(self) -> PinnedSQLiteCheckpoint:
        return self.checkpoints[-1]


@dataclass(frozen=True, slots=True)
class VerifiedPinnedSQLiteCheckpointChain:
    """Read-only proof of an exact pre-publication checkpoint lineage."""

    final_database_reference: str
    checkpoints: tuple[PinnedSQLiteCheckpoint, ...]

    @property
    def latest_checkpoint(self) -> PinnedSQLiteCheckpoint:
        return self.checkpoints[-1]


@dataclass(frozen=True, slots=True)
class _PinnedSQLiteEnrollmentBinding:
    parent_writer: GovernedWebCampaignParentWriter
    parent_run_id: str
    campaign_plan_digest: str
    witness_root_digest: str


@final
class _PinnedSQLiteFreshAuthority:
    """Opaque one-use binding from an already sealed external parent root."""

    __slots__ = (
        "_campaign_id",
        "_consumed",
        "_factory_token",
        "_lock",
        "_parent_writer",
        "_path",
        "_store_kind",
        "_witness_root_digest",
        "_workspace",
    )

    def __new__(cls, *_args: object, **_kwargs: object) -> _PinnedSQLiteFreshAuthority:
        raise TypeError("pinned SQLite fresh authorities are issuer-created only")

    def __init_subclass__(cls) -> None:
        raise TypeError("pinned SQLite fresh authorities cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise AttributeError("pinned SQLite fresh authorities are immutable")

    def __delattr__(self, _name: str) -> NoReturn:
        raise AttributeError("pinned SQLite fresh authorities are immutable")

    def __copy__(self) -> NoReturn:
        raise TypeError("pinned SQLite fresh authorities cannot be copied")

    def __deepcopy__(self, _memo: object) -> NoReturn:
        raise TypeError("pinned SQLite fresh authorities cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("pinned SQLite fresh authorities cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("pinned SQLite fresh authorities cannot be serialized")


def _issue_pinned_sqlite_fresh_authority(
    path: Path,
    *,
    store_kind: str,
    campaign_id: str,
    witness_root_digest: str,
    parent_writer: object,
) -> _PinnedSQLiteFreshAuthority:
    """Issue one code-owned first-creation binding from a verified parent root."""

    from pajin.web_assessment.governed_campaign_evidence import (
        GovernedWebCampaignParentWriter,
    )

    workspace = active_pinned_workspace_identity()
    relative = pinned_workspace_relative_path(path, label="pinned SQLite authority path")
    if workspace is None or relative is None:
        raise PinnedSQLiteError("pinned SQLite requires an active pinned workspace")
    if (
        len(relative.parts) != 2
        or _STORE_KIND_PATTERN.fullmatch(store_kind) is None
        or _CAMPAIGN_PATTERN.fullmatch(campaign_id) is None
        or _SHA256_PATTERN.fullmatch(witness_root_digest) is None
        or type(parent_writer) is not GovernedWebCampaignParentWriter
        or parent_writer.current_root_digest != witness_root_digest
        or parent_writer.plan.campaign_id != campaign_id
    ):
        raise PinnedSQLiteError("pinned SQLite fresh authority binding is invalid")
    authority = object.__new__(_PinnedSQLiteFreshAuthority)
    object.__setattr__(authority, "_factory_token", _FRESH_AUTHORITY_FACTORY_TOKEN)
    object.__setattr__(authority, "_workspace", workspace)
    object.__setattr__(authority, "_path", relative.as_posix())
    object.__setattr__(authority, "_store_kind", store_kind)
    object.__setattr__(authority, "_campaign_id", campaign_id)
    object.__setattr__(authority, "_witness_root_digest", witness_root_digest)
    object.__setattr__(authority, "_parent_writer", parent_writer)
    object.__setattr__(authority, "_consumed", False)
    object.__setattr__(authority, "_lock", threading.Lock())
    return authority


def _consume_pinned_sqlite_fresh_authority(
    authority: object,
    *,
    workspace: PinnedWorkspaceIdentity,
    path: str,
    store_kind: str,
    campaign_id: str,
) -> _PinnedSQLiteEnrollmentBinding:
    if type(authority) is not _PinnedSQLiteFreshAuthority:
        raise PinnedSQLiteError(
            "pinned SQLite creation requires a sealed-parent fresh authority"
        )
    lock = object.__getattribute__(authority, "_lock")
    if not isinstance(lock, type(threading.Lock())):
        raise PinnedSQLiteError("pinned SQLite fresh authority is invalid")
    with lock:
        if (
            object.__getattribute__(authority, "_factory_token")
            is not _FRESH_AUTHORITY_FACTORY_TOKEN
            or object.__getattribute__(authority, "_workspace") != workspace
            or object.__getattribute__(authority, "_path") != path
            or object.__getattribute__(authority, "_store_kind") != store_kind
            or object.__getattribute__(authority, "_campaign_id") != campaign_id
            or object.__getattribute__(authority, "_consumed")
        ):
            raise PinnedSQLiteError("pinned SQLite fresh authority differs or was consumed")
        parent_writer = object.__getattribute__(authority, "_parent_writer")
        try:
            parent_writer._consume_database_fresh_authority_binding(
                path=path,
                store_kind=store_kind,
                campaign_id=campaign_id,
                witness_root_digest=object.__getattribute__(
                    authority,
                    "_witness_root_digest",
                ),
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise PinnedSQLiteError(
                "pinned SQLite sealed-parent fresh authority is no longer current"
            ) from exc
        object.__setattr__(authority, "_consumed", True)
        plan = parent_writer.plan
        return _PinnedSQLiteEnrollmentBinding(
            parent_writer=parent_writer,
            parent_run_id=parent_writer.parent_run_id,
            campaign_plan_digest=plan.campaign_plan_digest,
            witness_root_digest=object.__getattribute__(
                authority,
                "_witness_root_digest",
            ),
        )


class _PinnedParent:
    def __init__(
        self,
        *,
        workspace: PinnedWorkspaceIdentity,
        name: str,
        root_fd: int,
        directory_fd: int,
        identity: PinnedWorkspaceIdentity,
    ) -> None:
        self.workspace = workspace
        self.name = name
        self.root_fd = root_fd
        self.directory_fd = directory_fd
        self.identity = identity
        self.references = 1

    @classmethod
    def create(cls, name: str) -> _PinnedParent:
        workspace = active_pinned_workspace_identity()
        if workspace is None:
            raise PinnedSQLiteError("pinned SQLite requires an active pinned workspace")
        root_fd = os.open(".", _directory_flags())
        try:
            if _identity(os.fstat(root_fd)) != workspace:
                raise PinnedSQLiteError("pinned SQLite workspace descriptor differs")
            _require_component_available(root_fd, name)
            try:
                os.mkdir(name, mode=0o700, dir_fd=root_fd)
                os.fsync(root_fd)
            except FileExistsError:
                pass
            directory_fd = os.open(name, _directory_flags(), dir_fd=root_fd)
            try:
                observed = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                opened = os.fstat(directory_fd)
                identity = _identity(opened)
                if (
                    _identity(observed) != identity
                    or identity.uid != os.geteuid()
                    or stat.S_IMODE(opened.st_mode) != 0o700
                ):
                    raise PinnedSQLiteError(
                        "pinned SQLite parent is not the exact private directory"
                    )
                os.set_inheritable(root_fd, False)
                os.set_inheritable(directory_fd, False)
                return cls(
                    workspace=workspace,
                    name=name,
                    root_fd=root_fd,
                    directory_fd=directory_fd,
                    identity=identity,
                )
            except BaseException:
                os.close(directory_fd)
                raise
        except BaseException:
            os.close(root_fd)
            raise

    def require_exact_link(self) -> None:
        current = active_pinned_workspace_identity()
        if current != self.workspace or _identity(os.fstat(self.root_fd)) != self.workspace:
            raise PinnedSQLiteError("pinned SQLite workspace identity changed")
        try:
            observed = os.stat(self.name, dir_fd=self.root_fd, follow_symlinks=False)
            opened = os.fstat(self.directory_fd)
            observed_identity = _identity(observed)
            opened_identity = _identity(opened)
        except (OSError, PinnedSQLiteError) as exc:
            raise PinnedSQLiteError("pinned SQLite parent link changed") from exc
        if observed_identity != self.identity or opened_identity != self.identity:
            raise PinnedSQLiteError("pinned SQLite parent link changed")

    def close(self) -> None:
        os.close(self.directory_fd)
        os.close(self.root_fd)


_PARENTS: dict[tuple[int, int, str], _PinnedParent] = {}
_DATABASES: dict[tuple[int, int, str], PinnedMemorySQLite] = {}


def _workspace_key(identity: PinnedWorkspaceIdentity, path: str) -> tuple[int, int, str]:
    return (identity.device, identity.inode, path)


def _staging_prefix(path: str) -> str:
    return f".pajin-sqlite-{sha256(path.encode()).hexdigest()[:32]}-"


def _require_no_prior_artifacts(
    parent: _PinnedParent,
    *,
    path: str,
    leaf: str,
    store_kind: str,
) -> None:
    path_digest = _enrollment_path_digest(store_kind=store_kind, path=path)
    parent_digest = _enrollment_parent_digest(
        store_kind=store_kind,
        leaf=leaf,
        parent_identity=parent.identity,
    )
    enrollment_prefix = _component_key(f"{_ENROLLMENT_NAME_PREFIX}{store_kind}-")
    for existing in os.listdir(parent.root_fd):
        if (
            _component_key(existing).startswith(enrollment_prefix)
            and (f"-{path_digest}-" in existing or existing.endswith(f"-{parent_digest}.json"))
        ):
            raise PinnedSQLiteError(
                "pinned SQLite namespace is already permanently enrolled"
            )
    checkpoint_prefix = _component_key(f".{leaf}.checkpoint-")
    for existing in os.listdir(parent.directory_fd):
        if _component_key(existing).startswith(checkpoint_prefix):
            raise PinnedSQLiteError(
                "pinned SQLite has a terminal incomplete checkpoint lineage"
            )
    staging_prefix = _component_key(_staging_prefix(path))
    for existing in os.listdir(parent.root_fd):
        if _component_key(existing).startswith(staging_prefix):
            raise PinnedSQLiteError(
                "pinned SQLite has a terminal incomplete staging artifact"
            )


def _acquire_parent(name: str) -> _PinnedParent:
    workspace = active_pinned_workspace_identity()
    if workspace is None:
        raise PinnedSQLiteError("pinned SQLite requires an active pinned workspace")
    key = _workspace_key(workspace, name)
    with _REGISTRY_LOCK:
        existing = _PARENTS.get(key)
        if existing is not None:
            existing.require_exact_link()
            existing.references += 1
            return existing
        parent = _PinnedParent.create(name)
        _PARENTS[key] = parent
        return parent


def _release_parent(parent: _PinnedParent) -> None:
    key = _workspace_key(parent.workspace, parent.name)
    with _REGISTRY_LOCK:
        current = _PARENTS.get(key)
        if current is not parent:
            return
        parent.references -= 1
        if parent.references == 0:
            _PARENTS.pop(key, None)
            parent.close()


class PinnedMemorySQLite:
    """One shared in-memory SQLite database bound to a pinned final location."""

    def __init__(
        self,
        *,
        path: Path,
        parent: _PinnedParent,
        store_kind: str,
        campaign_id: str,
        schema_digest: str,
        max_bytes: int,
        owner_authority: object,
        checkpoint_metadata: Callable[[sqlite3.Connection], dict[str, object]],
        checkpoint_observer: Callable[[PinnedSQLiteCheckpoint], None],
        enrollment_binding: _PinnedSQLiteEnrollmentBinding,
    ) -> None:
        self.path = path
        self._parent = parent
        self.store_kind = store_kind
        self.campaign_id = campaign_id
        self.schema_digest = schema_digest
        self.max_bytes = max_bytes
        self._owner_authority = owner_authority
        self._checkpoint_metadata = checkpoint_metadata
        self._enrollment_binding = enrollment_binding
        self._leaf = path.name
        self._enrollment_name = _governed_enrollment_name(
            path=path.as_posix(),
            store_kind=store_kind,
            leaf=path.name,
            parent_identity=parent.identity,
        )
        self._uri = f"file:pajin-{store_kind}-{uuid.uuid4().hex}?mode=memory&cache=shared"
        self._lock = threading.RLock()
        self._frozen = False
        self._terminal_error = False
        self._closed = False
        self._publication: PinnedSQLitePublication | None = None
        self._enrollment_publication: PinnedSQLitePublication | None = None
        self._latest_checkpoint: PinnedSQLiteCheckpoint | None = None
        self._checkpoints: list[PinnedSQLiteCheckpoint] = []
        self._checkpoint_observer = checkpoint_observer
        self._keeper = sqlite3.connect(
            self._uri,
            uri=True,
            isolation_level=None,
            check_same_thread=False,
        )
        self._configure(self._keeper, readonly=False)
        mode = self._keeper.execute("PRAGMA journal_mode = MEMORY").fetchone()
        if mode is None or str(mode[0]).lower() != "memory":
            self._keeper.close()
            raise PinnedSQLiteError("governed SQLite requires in-memory journal mode")

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        store_kind: str,
        campaign_id: str,
        schema_digest: str,
        max_bytes: int,
        owner_authority: object,
        checkpoint_metadata: Callable[[sqlite3.Connection], dict[str, object]],
        checkpoint_observer: Callable[[PinnedSQLiteCheckpoint], None],
        fresh_authority: object,
    ) -> PinnedMemorySQLite:
        if not isinstance(path, Path):
            raise TypeError("pinned SQLite path must be a Path")
        relative = pinned_workspace_relative_path(path, label="pinned SQLite path")
        if relative is None:
            raise PinnedSQLiteError("pinned SQLite requires an active pinned workspace")
        if len(relative.parts) != 2:
            raise ValueError("pinned SQLite path must have one parent and one file component")
        parent_name = _validate_component(relative.parts[0], label="pinned SQLite parent")
        leaf = _validate_component(relative.parts[1], label="pinned SQLite file")
        if (
            _STORE_KIND_PATTERN.fullmatch(store_kind) is None
            or _CAMPAIGN_PATTERN.fullmatch(campaign_id) is None
            or _SHA256_PATTERN.fullmatch(schema_digest) is None
            or not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or not 4_096 <= max_bytes <= 512 * 1024 * 1024
            or owner_authority is None
            or not callable(checkpoint_metadata)
            or not callable(checkpoint_observer)
        ):
            raise ValueError("pinned SQLite authority metadata is invalid")
        workspace = active_pinned_workspace_identity()
        if workspace is None:
            raise PinnedSQLiteError("pinned SQLite requires an active pinned workspace")
        key = _workspace_key(workspace, relative.as_posix())
        with _REGISTRY_LOCK:
            if key in _DATABASES:
                raise FileExistsError("pinned SQLite database is already registered")
        enrollment_binding = _consume_pinned_sqlite_fresh_authority(
            fresh_authority,
            workspace=workspace,
            path=relative.as_posix(),
            store_kind=store_kind,
            campaign_id=campaign_id,
        )
        parent = _acquire_parent(parent_name)
        try:
            if parent.workspace != workspace:
                raise PinnedSQLiteError("pinned SQLite fresh workspace changed")
            parent.require_exact_link()
            _require_component_available(parent.directory_fd, leaf)
            _require_no_prior_artifacts(
                parent,
                path=relative.as_posix(),
                leaf=leaf,
                store_kind=store_kind,
            )
            try:
                os.stat(leaf, dir_fd=parent.directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError("pinned SQLite final database already exists")
            workspace = parent.workspace
            with _REGISTRY_LOCK:
                if key in _DATABASES:
                    raise FileExistsError("pinned SQLite database is already registered")
                database = cls(
                    path=relative,
                    parent=parent,
                    store_kind=store_kind,
                    campaign_id=campaign_id,
                    schema_digest=schema_digest,
                    max_bytes=max_bytes,
                    owner_authority=owner_authority,
                    checkpoint_metadata=checkpoint_metadata,
                    checkpoint_observer=checkpoint_observer,
                    enrollment_binding=enrollment_binding,
                )
                try:
                    database._publish_enrollment_marker()
                    _DATABASES[key] = database
                    return database
                except BaseException:
                    database._keeper.close()
                    database._closed = True
                    raise
        except BaseException:
            _release_parent(parent)
            raise

    @staticmethod
    def _configure(connection: sqlite3.Connection, *, readonly: bool) -> None:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA busy_timeout = 5000")
        if readonly:
            connection.execute("PRAGMA query_only = ON")

    def runtime_identity(
        self,
        *,
        owner_authority: object,
    ) -> tuple[tuple[int, int], tuple[int, int]]:
        self._require_owner(owner_authority)
        digest = sha256(
            (
                f"{self.store_kind}\0{self.campaign_id}\0{self.schema_digest}\0"
                f"{self._uri}"
            ).encode()
        ).digest()
        synthetic = (int.from_bytes(digest[:8], "big"), int.from_bytes(digest[8:16], "big"))
        return (
            (self._parent.identity.device, self._parent.identity.inode),
            synthetic,
        )

    @property
    def frozen(self) -> bool:
        return self._frozen

    def _require_owner(self, owner_authority: object) -> None:
        if owner_authority is not self._owner_authority:
            raise PinnedSQLiteError("pinned SQLite owner authority is invalid")

    def require_exact_runtime(self, *, owner_authority: object) -> None:
        self._require_owner(owner_authority)
        if self._closed:
            raise PinnedSQLiteError("pinned SQLite database is closed")
        self._parent.require_exact_link()
        workspace = self._parent.workspace
        key = _workspace_key(workspace, self.path.as_posix())
        with _REGISTRY_LOCK:
            if _DATABASES.get(key) is not self:
                raise PinnedSQLiteError("pinned SQLite registry identity changed")
        self._require_checkpoint_publications()

    def _require_checkpoint_publications(self) -> None:
        enrollment = self._enrollment_publication
        if enrollment is None:
            raise PinnedSQLiteError("pinned SQLite enrollment is unavailable")
        self._require_exact_root_publication(
            self._enrollment_name,
            enrollment,
        )
        for checkpoint in self._checkpoints:
            self._require_exact_publication(
                Path(checkpoint.database_reference).name,
                PinnedSQLitePublication(
                    reference=checkpoint.database_reference,
                    sha256=checkpoint.database_sha256,
                    size=checkpoint.database_size,
                ),
            )
            self._require_exact_publication(
                Path(checkpoint.manifest_reference).name,
                PinnedSQLitePublication(
                    reference=checkpoint.manifest_reference,
                    sha256=checkpoint.manifest_sha256,
                    size=checkpoint.manifest_size,
                ),
            )

    def _publish_enrollment_marker(self) -> None:
        workspace = self._parent.workspace
        parent = self._parent.identity
        binding = self._enrollment_binding
        material = {
            "apiVersion": _ENROLLMENT_API_VERSION,
            "kind": _ENROLLMENT_KIND,
            "storeKind": self.store_kind,
            "campaignId": self.campaign_id,
            "schemaDigest": self.schema_digest,
            "workspaceIdentity": {
                "device": workspace.device,
                "inode": workspace.inode,
                "uid": workspace.uid,
                "mode": stat.S_IMODE(workspace.mode),
            },
            "authorityParentIdentity": {
                "device": parent.device,
                "inode": parent.inode,
                "uid": parent.uid,
                "mode": stat.S_IMODE(parent.mode),
            },
            "finalDatabaseReference": self.path.as_posix(),
            "parentRunId": binding.parent_run_id,
            "campaignPlanDigest": binding.campaign_plan_digest,
            "externallyAckedParentRootDigest": binding.witness_root_digest,
        }
        digest = sha256(_ENROLLMENT_DIGEST_DOMAIN + _canonical_json(material)).hexdigest()
        payload = {**material, "enrollmentDigest": digest}
        encoded = _canonical_json(payload) + b"\n"
        descriptor = os.open(
            self._enrollment_name,
            _regular_write_flags(),
            0o600,
            dir_fd=self._parent.root_fd,
        )
        try:
            view = memoryview(encoded)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise PinnedSQLiteError("governed SQLite enrollment write was incomplete")
                written += count
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            opened = os.fstat(descriptor)
            named = os.stat(
                self._enrollment_name,
                dir_fd=self._parent.root_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_size != len(encoded)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise PinnedSQLiteError("governed SQLite enrollment identity is invalid")
            os.fsync(self._parent.root_fd)
            publication = PinnedSQLitePublication(
                reference=self._enrollment_name,
                sha256=sha256(encoded).hexdigest(),
                size=len(encoded),
            )
            self._enrollment_publication = publication
            self._require_exact_root_publication(self._enrollment_name, publication)
        finally:
            # A partially written claim is deliberately retained.  Once the
            # fresh parent authority was consumed, any ambiguous creation must
            # remain terminal rather than becoming fresh again.
            os.close(descriptor)

    @contextmanager
    def connection(
        self,
        *,
        readonly: bool,
        owner_authority: object,
    ) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self.require_exact_runtime(owner_authority=owner_authority)
            if self._frozen and not readonly:
                raise PinnedSQLiteError("pinned SQLite database is frozen")
            if not readonly and self._latest_checkpoint is not None:
                self._require_latest_checkpoint_external_ack()
            connection = sqlite3.connect(
                self._uri,
                uri=True,
                isolation_level=None,
            )
            try:
                self._configure(connection, readonly=readonly)
                yield connection
                if not readonly:
                    if connection.in_transaction:
                        self._frozen = True
                        self._terminal_error = True
                        raise PinnedSQLiteError(
                            "pinned SQLite write transaction did not finish"
                        )
                    self._checkpoint_after_commit(connection)
            finally:
                connection.close()
                try:
                    self.require_exact_runtime(owner_authority=owner_authority)
                except BaseException:
                    if not readonly:
                        self._frozen = True
                        self._terminal_error = True
                    raise

    def latest_checkpoint(
        self,
        *,
        owner_authority: object,
    ) -> PinnedSQLiteCheckpoint:
        self.require_exact_runtime(owner_authority=owner_authority)
        if self._latest_checkpoint is None:
            raise PinnedSQLiteError("pinned SQLite database has no durable checkpoint")
        return self._latest_checkpoint

    def enrollment_publication(
        self,
        *,
        owner_authority: object,
    ) -> PinnedSQLitePublication:
        """Return the exact create-only enrollment retained at the output root."""

        with self._lock:
            self.require_exact_runtime(owner_authority=owner_authority)
            publication = self._enrollment_publication
            if publication is None:
                raise PinnedSQLiteError("pinned SQLite enrollment is unavailable")
            return publication

    def install_checkpoint_observer(
        self,
        observer: Callable[[PinnedSQLiteCheckpoint], None],
        *,
        owner_authority: object,
    ) -> None:
        self.require_exact_runtime(owner_authority=owner_authority)
        if not callable(observer):
            raise TypeError("pinned SQLite checkpoint observer must be callable")
        if self._checkpoint_observer is not None:
            raise PinnedSQLiteError("pinned SQLite checkpoint observer is already installed")
        self._checkpoint_observer = observer
        if self._latest_checkpoint is not None:
            try:
                observer(self._latest_checkpoint)
                self._require_latest_checkpoint_external_ack()
            except BaseException:
                self._frozen = True
                self._terminal_error = True
                raise

    def _checkpoint_after_commit(self, connection: sqlite3.Connection) -> None:
        content = connection.serialize(name="main")
        if not content or len(content) > self.max_bytes:
            self._frozen = True
            self._terminal_error = True
            raise PinnedSQLiteError("serialized governed SQLite checkpoint is invalid")
        self._verify_serialized_database(content)
        database_digest = sha256(content).hexdigest()
        previous = self._latest_checkpoint
        ordinal = 1 if previous is None else previous.ordinal + 1
        if ordinal > 4_096:
            self._frozen = True
            self._terminal_error = True
            raise PinnedSQLiteError("governed SQLite checkpoint capacity is exhausted")
        try:
            state = self._checkpoint_metadata(connection)
        except BaseException as exc:
            self._frozen = True
            self._terminal_error = True
            raise PinnedSQLiteError("governed SQLite checkpoint state is invalid") from exc
        if not isinstance(state, dict) or not all(isinstance(key, str) for key in state):
            self._frozen = True
            self._terminal_error = True
            raise PinnedSQLiteError("governed SQLite checkpoint state is invalid")
        state_bytes = _canonical_json(state)
        database_name = (
            f".{self._leaf}.checkpoint-{ordinal:08d}-{database_digest}.sqlite3"
        )
        database_publication = self._publish_named_bytes(
            database_name,
            content,
            digest=database_digest,
        )
        material = {
            "apiVersion": "pajin.dev/pinned-sqlite-checkpoint/v1alpha1",
            "kind": "PinnedSQLiteCheckpoint",
            "storeKind": self.store_kind,
            "campaignId": self.campaign_id,
            "schemaDigest": self.schema_digest,
            "ordinal": ordinal,
            "previousManifestDigest": (
                previous.manifest_digest if previous is not None else None
            ),
            "databaseReference": database_publication.reference,
            "databaseSha256": database_digest,
            "databaseSize": len(content),
            "state": json.loads(state_bytes),
        }
        material_bytes = _canonical_json(material)
        manifest_digest = sha256(material_bytes).hexdigest()
        manifest = dict(material)
        manifest["manifestDigest"] = manifest_digest
        manifest_bytes = _canonical_json(manifest) + b"\n"
        manifest_name = (
            f".{self._leaf}.checkpoint-{ordinal:08d}-{manifest_digest}.json"
        )
        manifest_publication = self._publish_named_bytes(
            manifest_name,
            manifest_bytes,
            digest=sha256(manifest_bytes).hexdigest(),
        )
        checkpoint = PinnedSQLiteCheckpoint(
            ordinal=ordinal,
            database_reference=database_publication.reference,
            database_sha256=database_digest,
            database_size=database_publication.size,
            manifest_reference=manifest_publication.reference,
            manifest_digest=manifest_digest,
            manifest_sha256=manifest_publication.sha256,
            manifest_size=manifest_publication.size,
            previous_manifest_digest=(
                previous.manifest_digest if previous is not None else None
            ),
            state_json=state_bytes,
        )
        self._checkpoints.append(checkpoint)
        self._latest_checkpoint = checkpoint
        if self._checkpoint_observer is not None:
            try:
                self._checkpoint_observer(checkpoint)
                self._require_latest_checkpoint_external_ack()
            except BaseException:
                self._frozen = True
                self._terminal_error = True
                raise

    def _require_latest_checkpoint_external_ack(self) -> None:
        checkpoint = self._latest_checkpoint
        if checkpoint is None:
            raise PinnedSQLiteError("governed SQLite database has no checkpoint to acknowledge")
        writer = self._enrollment_binding.parent_writer
        try:
            verifier = writer._require_database_checkpoint_external_ack
        except AttributeError as exc:
            raise PinnedSQLiteError(
                "governed SQLite parent checkpoint authority is unavailable"
            ) from exc
        try:
            verifier(
                path=self.path.as_posix(),
                store_kind=self.store_kind,
                checkpoint=checkpoint,
            )
        except (TypeError, ValueError) as exc:
            raise PinnedSQLiteError(
                "governed SQLite checkpoint lacks its sealed external ACK"
            ) from exc

    def freeze_and_publish(self, *, owner_authority: object) -> PinnedSQLitePublication:
        """Freeze the live database and publish one complete immutable byte image."""

        with self._lock:
            self.require_exact_runtime(owner_authority=owner_authority)
            if self._publication is not None:
                self._require_exact_publication(self._leaf, self._publication)
                return self._publication
            if self._terminal_error:
                raise PinnedSQLiteError(
                    "governed SQLite has a terminal checkpoint failure"
                )
            self._require_latest_checkpoint_external_ack()
            self._frozen = True
            try:
                content = self._keeper.serialize(name="main")
                if not content or len(content) > self.max_bytes:
                    raise PinnedSQLiteError("serialized governed SQLite database is invalid")
                digest = sha256(content).hexdigest()
                self._verify_serialized_database(content)
                checkpoint = self.latest_checkpoint(owner_authority=owner_authority)
                if checkpoint.database_sha256 != digest:
                    raise PinnedSQLiteError(
                        "final governed SQLite bytes lack their durable checkpoint"
                    )
                publication = self._publish_named_bytes(
                    self._leaf,
                    content,
                    digest=digest,
                )
                self._publication = publication
                return publication
            except BaseException:
                # A failed freeze is terminal for this authority.  Reopening it
                # could permit an effect after ambiguous persistence.
                self._frozen = True
                self._terminal_error = True
                raise

    def _verify_serialized_database(self, content: bytes) -> None:
        _verify_sqlite_bytes(content)

    def _publish_named_bytes(
        self,
        destination: str,
        content: bytes,
        *,
        digest: str,
    ) -> PinnedSQLitePublication:
        parent = self._parent
        parent.require_exact_link()
        _validate_component(destination, label="pinned SQLite publication")
        _require_component_available(parent.directory_fd, destination)
        staging = (
            f"{_staging_prefix(self.path.as_posix())}"
            f"{sha256(destination.encode()).hexdigest()[:16]}-{uuid.uuid4().hex}.staging"
        )
        descriptor = os.open(
            staging,
            _regular_write_flags(),
            0o600,
            dir_fd=parent.root_fd,
        )
        staged_identity: tuple[int, int] | None = None
        linked = False
        try:
            view = memoryview(content)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise PinnedSQLiteError("governed SQLite staging write was incomplete")
                written += count
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            opened = os.fstat(descriptor)
            staged_identity = (opened.st_dev, opened.st_ino)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_size != len(content)
            ):
                raise PinnedSQLiteError("governed SQLite staging identity is invalid")
            named = os.stat(staging, dir_fd=parent.root_fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != staged_identity:
                raise PinnedSQLiteError("governed SQLite staging name changed")
            parent.require_exact_link()
            os.link(
                staging,
                destination,
                src_dir_fd=parent.root_fd,
                dst_dir_fd=parent.directory_fd,
                follow_symlinks=False,
            )
            linked = True
            final = os.stat(destination, dir_fd=parent.directory_fd, follow_symlinks=False)
            staged = os.stat(staging, dir_fd=parent.root_fd, follow_symlinks=False)
            if (
                (final.st_dev, final.st_ino) != staged_identity
                or (staged.st_dev, staged.st_ino) != staged_identity
                or final.st_nlink != 2
                or staged.st_nlink != 2
            ):
                raise PinnedSQLiteError("governed SQLite no-replace publication changed")
            # Make the destination link durable before removing the only
            # recoverable staging name.  A crash before the unlink leaves a
            # fail-closed extra staging artifact rather than an absent result.
            os.fsync(parent.directory_fd)
            parent.require_exact_link()
            os.unlink(staging, dir_fd=parent.root_fd)
            staging = ""
            os.fsync(parent.root_fd)
            parent.require_exact_link()
            publication = PinnedSQLitePublication(
                reference=f"{self.path.parent.as_posix()}/{destination}",
                sha256=digest,
                size=len(content),
            )
            self._require_exact_publication(destination, publication)
            return publication
        except BaseException:
            if linked and staged_identity is not None:
                self._unlink_if_exact(
                    parent.directory_fd,
                    destination,
                    staged_identity,
                )
                with suppress(OSError):
                    os.fsync(parent.directory_fd)
            if staging and staged_identity is not None:
                self._unlink_if_exact(parent.root_fd, staging, staged_identity)
            raise
        finally:
            os.close(descriptor)

    @staticmethod
    def _unlink_if_exact(directory_fd: int, name: str, expected: tuple[int, int]) -> None:
        try:
            observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return
        if (observed.st_dev, observed.st_ino) == expected:
            with suppress(OSError):
                os.unlink(name, dir_fd=directory_fd)

    def _require_exact_publication(
        self,
        name: str,
        publication: PinnedSQLitePublication,
    ) -> None:
        self._parent.require_exact_link()
        self._require_exact_publication_at(
            self._parent.directory_fd,
            name,
            publication,
        )
        self._parent.require_exact_link()

    def _require_exact_root_publication(
        self,
        name: str,
        publication: PinnedSQLitePublication,
    ) -> None:
        self._parent.require_exact_link()
        self._require_exact_publication_at(
            self._parent.root_fd,
            name,
            publication,
        )
        self._parent.require_exact_link()

    def _require_exact_publication_at(
        self,
        directory_fd: int,
        name: str,
        publication: PinnedSQLitePublication,
    ) -> None:
        try:
            descriptor = os.open(
                name,
                _regular_read_flags(),
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise PinnedSQLiteError(
                "published governed SQLite artifact is missing or unsafe"
            ) from exc
        try:
            try:
                opened = os.fstat(descriptor)
                named = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise PinnedSQLiteError(
                    "published governed SQLite artifact identity is unavailable"
                ) from exc
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or opened.st_size != publication.size
            ):
                raise PinnedSQLiteError("published governed SQLite identity is invalid")
            hasher = sha256()
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, self.max_bytes + 1))
                if not chunk:
                    break
                hasher.update(chunk)
            if hasher.hexdigest() != publication.sha256:
                raise PinnedSQLiteError("published governed SQLite bytes changed")
        finally:
            os.close(descriptor)

    def close(self, *, owner_authority: object) -> None:
        self._require_owner(owner_authority)
        with self._lock:
            if self._closed:
                return
            workspace = self._parent.workspace
            key = _workspace_key(workspace, self.path.as_posix())
            with _REGISTRY_LOCK:
                if _DATABASES.get(key) is self:
                    _DATABASES.pop(key, None)
            self._keeper.close()
            self._closed = True
            _release_parent(self._parent)


def _verify_sqlite_bytes(content: bytes) -> None:
    verifier = sqlite3.connect(":memory:", isolation_level=None)
    try:
        verifier.deserialize(content, name="main")
        verifier.execute("PRAGMA query_only = ON")
        result = verifier.execute("PRAGMA quick_check").fetchone()
        if result is None or str(result[0]).lower() != "ok":
            raise PinnedSQLiteError("serialized governed SQLite database failed integrity")
    except sqlite3.DatabaseError as exc:
        raise PinnedSQLiteError("serialized governed SQLite database is unreadable") from exc
    finally:
        verifier.close()


def _strict_database_reference(reference: str, *, label: str) -> tuple[str, str]:
    if not isinstance(reference, str):
        raise TypeError(f"{label} must be a string")
    path = Path(reference)
    if path.is_absolute() or len(path.parts) != 2 or path.as_posix() != reference:
        raise PinnedSQLiteError(f"{label} must contain exactly two relative components")
    return (
        _validate_component(path.parts[0], label=f"{label} parent"),
        _validate_component(path.parts[1], label=f"{label} leaf"),
    )


def _read_verified_regular_at(
    directory_fd: int,
    name: str,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    try:
        descriptor = os.open(name, _regular_read_flags(), dir_fd=directory_fd)
    except OSError as exc:
        raise PinnedSQLiteError(f"{label} is missing or unsafe") from exc
    try:
        before = os.fstat(descriptor)
        try:
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise PinnedSQLiteError(f"{label} identity is unavailable") from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
            or before.st_size > max_bytes
        ):
            raise PinnedSQLiteError(f"{label} identity is invalid")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise PinnedSQLiteError(f"{label} identity disappeared while reading") from exc
        if (
            len(content) > max_bytes
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
        ):
            raise PinnedSQLiteError(f"{label} changed while reading")
        return content
    finally:
        os.close(descriptor)


def _verified_checkpoint_manifest(
    parent_fd: int,
    *,
    parent_name: str,
    leaf: str,
    store_kind: str,
    campaign_id: str,
    schema_digest: str,
    ordinal: int,
    manifest_digest: str,
    max_database_bytes: int,
) -> tuple[PinnedSQLiteCheckpoint, set[str]]:
    manifest_name = f".{leaf}.checkpoint-{ordinal:08d}-{manifest_digest}.json"
    manifest_content = _read_verified_regular_at(
        parent_fd,
        manifest_name,
        max_bytes=4 * 1024 * 1024,
        label="pinned SQLite checkpoint manifest",
    )
    try:
        raw = parse_strict_json_bytes(
            manifest_content,
            label="pinned SQLite checkpoint manifest",
            max_bytes=4 * 1024 * 1024,
            max_depth=32,
            max_nodes=50_000,
        )
    except ValueError as exc:
        raise PinnedSQLiteError("pinned SQLite checkpoint manifest is invalid") from exc
    keys = {
        "apiVersion",
        "kind",
        "storeKind",
        "campaignId",
        "schemaDigest",
        "ordinal",
        "previousManifestDigest",
        "databaseReference",
        "databaseSha256",
        "databaseSize",
        "state",
        "manifestDigest",
    }
    if not isinstance(raw, dict) or set(raw) != keys:
        raise PinnedSQLiteError("pinned SQLite checkpoint manifest shape differs")
    manifest = cast(dict[str, object], raw)
    material = {key: value for key, value in manifest.items() if key != "manifestDigest"}
    if _canonical_json(manifest) + b"\n" != manifest_content:
        raise PinnedSQLiteError("pinned SQLite checkpoint manifest is not canonical")
    computed_manifest_digest = sha256(_canonical_json(material)).hexdigest()
    previous_digest = manifest["previousManifestDigest"]
    database_digest = manifest["databaseSha256"]
    database_size = manifest["databaseSize"]
    state = manifest["state"]
    database_name = f".{leaf}.checkpoint-{ordinal:08d}-{database_digest}.sqlite3"
    database_reference = f"{parent_name}/{database_name}"
    manifest_reference = f"{parent_name}/{manifest_name}"
    if (
        manifest["apiVersion"] != "pajin.dev/pinned-sqlite-checkpoint/v1alpha1"
        or manifest["kind"] != "PinnedSQLiteCheckpoint"
        or manifest["storeKind"] != store_kind
        or manifest["campaignId"] != campaign_id
        or manifest["schemaDigest"] != schema_digest
        or type(manifest["ordinal"]) is not int
        or manifest["ordinal"] != ordinal
        or manifest["manifestDigest"] != manifest_digest
        or computed_manifest_digest != manifest_digest
        or not isinstance(database_digest, str)
        or _SHA256_PATTERN.fullmatch(database_digest) is None
        or type(database_size) is not int
        or not 1 <= database_size <= max_database_bytes
        or manifest["databaseReference"] != database_reference
        or not isinstance(state, dict)
        or not all(isinstance(key, str) for key in state)
        or (
            previous_digest is not None
            and (
                not isinstance(previous_digest, str)
                or _SHA256_PATTERN.fullmatch(previous_digest) is None
            )
        )
    ):
        raise PinnedSQLiteError("pinned SQLite checkpoint manifest binding differs")
    database_content = _read_verified_regular_at(
        parent_fd,
        database_name,
        max_bytes=max_database_bytes,
        label="pinned SQLite checkpoint database",
    )
    if (
        len(database_content) != database_size
        or sha256(database_content).hexdigest() != database_digest
    ):
        raise PinnedSQLiteError("pinned SQLite checkpoint database digest differs")
    _verify_sqlite_bytes(database_content)
    state_json = _canonical_json(state)
    checkpoint = PinnedSQLiteCheckpoint(
        ordinal=ordinal,
        database_reference=database_reference,
        database_sha256=database_digest,
        database_size=database_size,
        manifest_reference=manifest_reference,
        manifest_digest=manifest_digest,
        manifest_sha256=sha256(manifest_content).hexdigest(),
        manifest_size=len(manifest_content),
        previous_manifest_digest=previous_digest,
        state_json=state_json,
    )
    return checkpoint, {manifest_name, database_name}


def _validate_verification_expectations(
    *,
    store_kind: str,
    campaign_id: str,
    schema_digest: str,
    latest_manifest_digest: str,
    final_database_sha256: str,
    latest_ordinal: int,
    max_database_bytes: int,
) -> None:
    if (
        _STORE_KIND_PATTERN.fullmatch(store_kind) is None
        or _CAMPAIGN_PATTERN.fullmatch(campaign_id) is None
        or _SHA256_PATTERN.fullmatch(schema_digest) is None
        or _SHA256_PATTERN.fullmatch(latest_manifest_digest) is None
        or _SHA256_PATTERN.fullmatch(final_database_sha256) is None
        or type(latest_ordinal) is not int
        or not 1 <= latest_ordinal <= 4_096
        or type(max_database_bytes) is not int
        or not 4_096 <= max_database_bytes <= 512 * 1024 * 1024
    ):
        raise ValueError("pinned SQLite verification expectation is invalid")


def _open_verified_root(path: Path) -> tuple[int, PinnedWorkspaceIdentity]:
    try:
        descriptor = os.open(path, _directory_flags())
    except OSError as exc:
        raise PinnedSQLiteError("pinned SQLite verification root is unsafe") from exc
    try:
        identity = _identity(os.fstat(descriptor))
        named = os.stat(path, follow_symlinks=False)
        if (
            _identity(named) != identity
            or not stat.S_ISDIR(named.st_mode)
            or named.st_uid != os.geteuid()
        ):
            raise PinnedSQLiteError("pinned SQLite verification root identity differs")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _open_verified_authority(root_fd: int, parent_name: str) -> int:
    _require_component_available(root_fd, parent_name)
    try:
        descriptor = os.open(parent_name, _directory_flags(), dir_fd=root_fd)
    except OSError as exc:
        raise PinnedSQLiteError("pinned SQLite authority directory is unsafe") from exc
    try:
        opened = os.fstat(descriptor)
        named = os.stat(parent_name, dir_fd=root_fd, follow_symlinks=False)
        if (
            _identity(opened) != _identity(named)
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise PinnedSQLiteError("pinned SQLite authority directory identity differs")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _verify_governed_enrollment(
    root_fd: int,
    *,
    root_identity: PinnedWorkspaceIdentity,
    parent_identity: PinnedWorkspaceIdentity,
    final_database_reference: str,
    parent_name: str,
    leaf: str,
    store_kind: str,
    campaign_id: str,
    schema_digest: str,
) -> PinnedSQLitePublication:
    enrollment_name = _governed_enrollment_name(
        path=final_database_reference,
        store_kind=store_kind,
        leaf=leaf,
        parent_identity=parent_identity,
    )
    path_digest = _enrollment_path_digest(
        store_kind=store_kind,
        path=final_database_reference,
    )
    parent_digest = _enrollment_parent_digest(
        store_kind=store_kind,
        leaf=leaf,
        parent_identity=parent_identity,
    )
    prefix = _component_key(f"{_ENROLLMENT_NAME_PREFIX}{store_kind}-")
    relevant = {
        name
        for name in os.listdir(root_fd)
        if _component_key(name).startswith(prefix)
        and (f"-{path_digest}-" in name or name.endswith(f"-{parent_digest}.json"))
    }
    if relevant != {enrollment_name}:
        raise PinnedSQLiteError("pinned SQLite enrollment inventory differs")
    content = _read_verified_regular_at(
        root_fd,
        enrollment_name,
        max_bytes=16 * 1024,
        label="pinned SQLite enrollment",
    )
    try:
        raw = parse_strict_json_bytes(
            content,
            label="pinned SQLite enrollment",
            max_bytes=16 * 1024,
            max_depth=8,
            max_nodes=64,
        )
    except ValueError as exc:
        raise PinnedSQLiteError("pinned SQLite enrollment is invalid") from exc
    expected_keys = {
        "apiVersion",
        "kind",
        "storeKind",
        "campaignId",
        "schemaDigest",
        "workspaceIdentity",
        "authorityParentIdentity",
        "finalDatabaseReference",
        "parentRunId",
        "campaignPlanDigest",
        "externallyAckedParentRootDigest",
        "enrollmentDigest",
    }
    if not isinstance(raw, dict) or set(raw) != expected_keys:
        raise PinnedSQLiteError("pinned SQLite enrollment shape differs")
    enrollment = cast(dict[str, object], raw)
    material = {
        key: value for key, value in enrollment.items() if key != "enrollmentDigest"
    }
    digest = enrollment["enrollmentDigest"]
    expected_workspace = {
        "device": root_identity.device,
        "inode": root_identity.inode,
        "uid": root_identity.uid,
        "mode": stat.S_IMODE(root_identity.mode),
    }
    expected_parent = {
        "device": parent_identity.device,
        "inode": parent_identity.inode,
        "uid": parent_identity.uid,
        "mode": stat.S_IMODE(parent_identity.mode),
    }
    if (
        content != _canonical_json(enrollment) + b"\n"
        or enrollment["apiVersion"] != _ENROLLMENT_API_VERSION
        or enrollment["kind"] != _ENROLLMENT_KIND
        or enrollment["storeKind"] != store_kind
        or enrollment["campaignId"] != campaign_id
        or enrollment["schemaDigest"] != schema_digest
        or enrollment["workspaceIdentity"] != expected_workspace
        or enrollment["authorityParentIdentity"] != expected_parent
        or enrollment["finalDatabaseReference"]
        != f"{parent_name}/{leaf}"
        or not isinstance(enrollment["parentRunId"], str)
        or _RUN_ID_PATTERN.fullmatch(enrollment["parentRunId"]) is None
        or not isinstance(enrollment["campaignPlanDigest"], str)
        or _SHA256_PATTERN.fullmatch(enrollment["campaignPlanDigest"]) is None
        or not isinstance(enrollment["externallyAckedParentRootDigest"], str)
        or _SHA256_PATTERN.fullmatch(
            enrollment["externallyAckedParentRootDigest"]
        )
        is None
        or not isinstance(digest, str)
        or _SHA256_PATTERN.fullmatch(digest) is None
        or digest != sha256(_ENROLLMENT_DIGEST_DOMAIN + _canonical_json(material)).hexdigest()
    ):
        raise PinnedSQLiteError("pinned SQLite enrollment binding differs")
    return PinnedSQLitePublication(
        reference=enrollment_name,
        sha256=sha256(content).hexdigest(),
        size=len(content),
    )


def _require_exact_checkpoint_inventory(
    parent_fd: int,
    *,
    leaf: str,
    expected_checkpoint_names: set[str],
    final_required: bool = True,
) -> None:
    relevant_prefix = _component_key(f".{leaf}.checkpoint-")
    relevant_keys = {
        _component_key(leaf),
        _component_key(f"{leaf}-journal"),
        _component_key(f"{leaf}-wal"),
        _component_key(f"{leaf}-shm"),
    }
    observed: dict[str, str] = {}
    for name in os.listdir(parent_fd):
        key = _component_key(name)
        if key.startswith(relevant_prefix) or key in relevant_keys:
            if key in observed:
                raise PinnedSQLiteError("pinned SQLite artifact has an alias collision")
            observed[key] = name
    expected = {*expected_checkpoint_names, *({leaf} if final_required else set())}
    if set(observed.values()) != expected:
        raise PinnedSQLiteError("pinned SQLite checkpoint inventory differs")


def load_verified_pinned_sqlite_checkpoint_chain(
    output_root: Path,
    *,
    final_database_reference: str,
    expected_store_kind: str,
    expected_campaign_id: str,
    expected_schema_digest: str,
    expected_latest_manifest_reference: str,
    expected_latest_manifest_digest: str,
    expected_latest_ordinal: int,
    expected_latest_database_sha256: str,
    max_database_bytes: int,
) -> VerifiedPinnedSQLiteCheckpointChain:
    """Verify a complete exact checkpoint chain before final DB publication."""

    if not isinstance(output_root, Path):
        raise TypeError("pinned SQLite verification root must be a Path")
    parent_name, leaf = _strict_database_reference(
        final_database_reference,
        label="pinned SQLite final database reference",
    )
    _validate_verification_expectations(
        store_kind=expected_store_kind,
        campaign_id=expected_campaign_id,
        schema_digest=expected_schema_digest,
        latest_manifest_digest=expected_latest_manifest_digest,
        final_database_sha256=expected_latest_database_sha256,
        latest_ordinal=expected_latest_ordinal,
        max_database_bytes=max_database_bytes,
    )
    expected_latest_name = (
        f".{leaf}.checkpoint-{expected_latest_ordinal:08d}-"
        f"{expected_latest_manifest_digest}.json"
    )
    if expected_latest_manifest_reference != f"{parent_name}/{expected_latest_name}":
        raise PinnedSQLiteError("pinned SQLite latest checkpoint reference differs")
    root_path = Path(os.path.abspath(output_root))
    root_fd, root_identity = _open_verified_root(root_path)
    parent_fd = -1
    try:
        parent_fd = _open_verified_authority(root_fd, parent_name)
        parent_identity = _identity(os.fstat(parent_fd))
        _verify_governed_enrollment(
            root_fd,
            root_identity=root_identity,
            parent_identity=parent_identity,
            final_database_reference=final_database_reference,
            parent_name=parent_name,
            leaf=leaf,
            store_kind=expected_store_kind,
            campaign_id=expected_campaign_id,
            schema_digest=expected_schema_digest,
        )
        checkpoints_reversed: list[PinnedSQLiteCheckpoint] = []
        expected_checkpoint_names: set[str] = set()
        current_digest: str | None = expected_latest_manifest_digest
        for ordinal in range(expected_latest_ordinal, 0, -1):
            if current_digest is None:
                raise PinnedSQLiteError("pinned SQLite checkpoint chain ended early")
            checkpoint, names = _verified_checkpoint_manifest(
                parent_fd,
                parent_name=parent_name,
                leaf=leaf,
                store_kind=expected_store_kind,
                campaign_id=expected_campaign_id,
                schema_digest=expected_schema_digest,
                ordinal=ordinal,
                manifest_digest=current_digest,
                max_database_bytes=max_database_bytes,
            )
            checkpoints_reversed.append(checkpoint)
            expected_checkpoint_names.update(names)
            current_digest = checkpoint.previous_manifest_digest
        if current_digest is not None:
            raise PinnedSQLiteError("pinned SQLite checkpoint chain has an earlier hidden head")
        checkpoints = tuple(reversed(checkpoints_reversed))
        if checkpoints[-1].database_sha256 != expected_latest_database_sha256:
            raise PinnedSQLiteError("pinned SQLite checkpoint database head differs")
        _require_exact_checkpoint_inventory(
            parent_fd,
            leaf=leaf,
            expected_checkpoint_names=expected_checkpoint_names,
            final_required=False,
        )
        staging_prefix = _component_key(_staging_prefix(final_database_reference))
        if any(
            _component_key(name).startswith(staging_prefix)
            for name in os.listdir(root_fd)
        ):
            raise PinnedSQLiteError("pinned SQLite staging inventory is not empty")
        root_after = os.stat(root_path, follow_symlinks=False)
        parent_named_after = os.stat(
            parent_name,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if (
            _identity(root_after) != root_identity
            or _identity(parent_named_after) != parent_identity
            or _identity(os.fstat(parent_fd)) != parent_identity
        ):
            raise PinnedSQLiteError("pinned SQLite checkpoint authority changed")
        return VerifiedPinnedSQLiteCheckpointChain(
            final_database_reference=final_database_reference,
            checkpoints=checkpoints,
        )
    except OSError as exc:
        raise PinnedSQLiteError("pinned SQLite checkpoint verification failed closed") from exc
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)


def load_verified_pinned_sqlite_database(
    output_root: Path,
    *,
    final_database_reference: str,
    expected_store_kind: str,
    expected_campaign_id: str,
    expected_schema_digest: str,
    expected_latest_manifest_reference: str,
    expected_latest_manifest_digest: str,
    expected_latest_ordinal: int,
    expected_final_database_sha256: str,
    expected_enrollment_reference: str,
    expected_enrollment_sha256: str,
    expected_enrollment_size: int,
    max_database_bytes: int,
) -> VerifiedPinnedSQLiteDatabase:
    """Verify an exact final DB plus every caller-anchored immutable checkpoint."""

    if not isinstance(output_root, Path):
        raise TypeError("pinned SQLite verification root must be a Path")
    parent_name, leaf = _strict_database_reference(
        final_database_reference,
        label="pinned SQLite final database reference",
    )
    _validate_verification_expectations(
        store_kind=expected_store_kind,
        campaign_id=expected_campaign_id,
        schema_digest=expected_schema_digest,
        latest_manifest_digest=expected_latest_manifest_digest,
        final_database_sha256=expected_final_database_sha256,
        latest_ordinal=expected_latest_ordinal,
        max_database_bytes=max_database_bytes,
    )
    if (
        not isinstance(expected_enrollment_reference, str)
        or not expected_enrollment_reference
        or expected_enrollment_reference in {".", ".."}
        or "/" in expected_enrollment_reference
        or "\x00" in expected_enrollment_reference
        or not isinstance(expected_enrollment_sha256, str)
        or _SHA256_PATTERN.fullmatch(expected_enrollment_sha256) is None
        or type(expected_enrollment_size) is not int
        or not 1 <= expected_enrollment_size <= 16 * 1024
    ):
        raise ValueError("pinned SQLite enrollment expectation is invalid")
    expected_latest_name = (
        f".{leaf}.checkpoint-{expected_latest_ordinal:08d}-"
        f"{expected_latest_manifest_digest}.json"
    )
    if expected_latest_manifest_reference != f"{parent_name}/{expected_latest_name}":
        raise PinnedSQLiteError("pinned SQLite latest checkpoint reference differs")
    root_path = Path(os.path.abspath(output_root))
    root_fd, root_identity = _open_verified_root(root_path)
    parent_fd = -1
    try:
        parent_fd = _open_verified_authority(root_fd, parent_name)
        parent_identity = _identity(os.fstat(parent_fd))
        enrollment_publication = _verify_governed_enrollment(
            root_fd,
            root_identity=root_identity,
            parent_identity=parent_identity,
            final_database_reference=final_database_reference,
            parent_name=parent_name,
            leaf=leaf,
            store_kind=expected_store_kind,
            campaign_id=expected_campaign_id,
            schema_digest=expected_schema_digest,
        )
        if enrollment_publication != PinnedSQLitePublication(
            reference=expected_enrollment_reference,
            sha256=expected_enrollment_sha256,
            size=expected_enrollment_size,
        ):
            raise PinnedSQLiteError("pinned SQLite enrollment publication differs")
        checkpoints_reversed: list[PinnedSQLiteCheckpoint] = []
        expected_checkpoint_names: set[str] = set()
        current_digest: str | None = expected_latest_manifest_digest
        for ordinal in range(expected_latest_ordinal, 0, -1):
            if current_digest is None:
                raise PinnedSQLiteError("pinned SQLite checkpoint chain ended early")
            checkpoint, names = _verified_checkpoint_manifest(
                parent_fd,
                parent_name=parent_name,
                leaf=leaf,
                store_kind=expected_store_kind,
                campaign_id=expected_campaign_id,
                schema_digest=expected_schema_digest,
                ordinal=ordinal,
                manifest_digest=current_digest,
                max_database_bytes=max_database_bytes,
            )
            checkpoints_reversed.append(checkpoint)
            expected_checkpoint_names.update(names)
            current_digest = checkpoint.previous_manifest_digest
        if current_digest is not None:
            raise PinnedSQLiteError("pinned SQLite checkpoint chain has an earlier hidden head")
        checkpoints = tuple(reversed(checkpoints_reversed))
        _require_exact_checkpoint_inventory(
            parent_fd,
            leaf=leaf,
            expected_checkpoint_names=expected_checkpoint_names,
        )
        staging_prefix = _component_key(_staging_prefix(final_database_reference))
        if any(
            _component_key(name).startswith(staging_prefix)
            for name in os.listdir(root_fd)
        ):
            raise PinnedSQLiteError("pinned SQLite staging inventory is not empty")
        final_content = _read_verified_regular_at(
            parent_fd,
            leaf,
            max_bytes=max_database_bytes,
            label="final governed SQLite database",
        )
        final_digest = sha256(final_content).hexdigest()
        latest = checkpoints[-1]
        if (
            final_digest != expected_final_database_sha256
            or final_digest != latest.database_sha256
            or len(final_content) != latest.database_size
        ):
            raise PinnedSQLiteError("final governed SQLite database differs from checkpoint head")
        _verify_sqlite_bytes(final_content)
        final_content_after = _read_verified_regular_at(
            parent_fd,
            leaf,
            max_bytes=max_database_bytes,
            label="final governed SQLite database post-verification",
        )
        root_after = os.stat(root_path, follow_symlinks=False)
        parent_named_after = os.stat(
            parent_name,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if (
            _identity(root_after) != root_identity
            or _identity(parent_named_after) != parent_identity
            or _identity(os.fstat(parent_fd)) != parent_identity
            or final_content_after != final_content
        ):
            raise PinnedSQLiteError("pinned SQLite verification root changed")
        return VerifiedPinnedSQLiteDatabase(
            final_publication=PinnedSQLitePublication(
                reference=final_database_reference,
                sha256=final_digest,
                size=len(final_content),
            ),
            enrollment_publication=enrollment_publication,
            checkpoints=checkpoints,
            database_bytes=final_content,
        )
    except OSError as exc:
        raise PinnedSQLiteError("pinned SQLite verification failed closed") from exc
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)

def pinned_memory_sqlite_for_path(
    path: Path,
    *,
    owner_authority: object,
) -> PinnedMemorySQLite | None:
    """Return the exact registered governed database for the active workspace."""

    workspace = active_pinned_workspace_identity()
    if workspace is None:
        return None
    relative = pinned_workspace_relative_path(path, label="pinned SQLite lookup path")
    if relative is None:
        return None
    key = _workspace_key(workspace, relative.as_posix())
    with _REGISTRY_LOCK:
        database = _DATABASES.get(key)
    if database is not None:
        database.require_exact_runtime(owner_authority=owner_authority)
    return database


__all__ = [
    "PinnedSQLiteCheckpoint",
    "PinnedSQLiteError",
    "PinnedSQLitePublication",
    "VerifiedPinnedSQLiteCheckpointChain",
    "VerifiedPinnedSQLiteDatabase",
    "is_governed_pinned_sqlite_namespace",
    "load_verified_pinned_sqlite_checkpoint_chain",
    "load_verified_pinned_sqlite_database",
]
