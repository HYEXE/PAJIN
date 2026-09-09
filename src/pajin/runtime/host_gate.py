"""Single-host activity exclusion for enrolled runtime and checkpoint operations."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from pajin.runtime.inventory import (
    HOST_ROOT_ENV,
    INVENTORY_PATH_ENV,
    INVENTORY_SHA256_ENV,
    RuntimeComponentFingerprint,
    RuntimeRole,
    host_root_digest,
    load_runtime_inventory,
    verify_runtime_inventory,
)
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes

if sys.platform != "win32":
    import fcntl

_GATE_FILE = "runtime-gate.json"
_MAX_GATE_BYTES = 4096
_ACTIVE: ContextVar[HostActivityLease | None] = ContextVar("pajin_host_activity", default=None)
_RECOVERY_COMPONENT: ContextVar[RuntimeComponentFingerprint | None] = ContextVar(
    "pajin_recovery_component", default=None,
)
_LEASE_AUTHORITY = object()


class HostActivityError(RuntimeError):
    """The host has no valid admission or cannot enter the requested activity mode."""


class HostGateIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    api_version: Literal["pajin.dev/host-runtime-gate/v1"] = Field(
        default="pajin.dev/host-runtime-gate/v1", alias="apiVersion",
    )
    gate_id: Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{32}$")] = Field(alias="gateId")
    inventory_id: Annotated[str, Field(strict=True, pattern=r"^[a-z][a-z0-9-]{0,63}$")] = Field(
        alias="inventoryId",
    )
    inventory_sha256: Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{64}$")] = Field(
        alias="inventorySha256",
    )
    root_sha256: Annotated[str, Field(strict=True, pattern=r"^[a-f0-9]{64}$")] = Field(
        alias="rootSha256",
    )

    def canonical(self) -> bytes:
        return self.model_dump_json(by_alias=True).encode("utf-8")


def _root_path(root: Path) -> Path:
    if sys.platform == "win32" or os.name != "posix":
        raise HostActivityError("enrolled host activity requires POSIX local file locking")
    if not root.is_absolute() or ".." in root.parts:
        raise HostActivityError("host runtime root must be an absolute, unambiguous path")
    for part in (root, *root.parents):
        if part.is_symlink() or (part.exists() and not part.is_dir()):
            raise HostActivityError("host runtime root requires regular directories")
    return root


def enroll_host_gate(
    root: Path, *, inventory_path: Path, inventory_sha256: str,
) -> HostGateIdentity:
    """Create one new private gate; never repair, replace or retire an existing gate."""
    root = _root_path(root)
    inventory = load_runtime_inventory(inventory_path, inventory_sha256)
    if inventory.host_root_sha256 != host_root_digest(root):
        raise HostActivityError("gate enrollment requires a v2 inventory bound to this host root")
    identity = HostGateIdentity(
        gateId=uuid4().hex, inventoryId=inventory.inventory_id, inventorySha256=inventory_sha256,
        rootSha256=host_root_digest(root),
    )
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    _root_path(root)
    if root.stat().st_mode & 0o077:
        raise HostActivityError("host runtime root must have private permissions")
    descriptor = os.open(
        root / _GATE_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    # An interrupted enrollment remains invalid; only the process owner can
    # reconcile it. Do not unlink a gate another process might already have opened.
    try:
        if inventory.recovery_policy is not None:
            from pajin.runtime.host_recovery import initialize_recovery_index

            state = root / "state"
            state.mkdir(mode=0o700, exist_ok=True)
            _root_path(state)
            if state.stat().st_mode & 0o077 or state.stat().st_uid != os.geteuid():
                raise HostActivityError("recovery state must be private and owned by this user")
            initialize_recovery_index(
                root, identity, inventory_bytes=read_bounded_regular_bytes(
                    inventory_path, max_bytes=64 * 1024,
                    label="recovery runtime inventory", require_single_link=True,
                ),
            )
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(identity.canonical())
            output.flush()
            os.fsync(descriptor)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(descriptor)
    return identity


class HostActivityLease:
    """One live kernel lock, not a serializable assertion that a host is stopped."""

    __slots__ = (
        "_active", "_descriptor", "_exclusive", "_identity", "_pid", "_recovery_required", "_root",
    )

    def __init__(
        self, *, root: Path, identity: HostGateIdentity, descriptor: int, exclusive: bool,
        _authority: object, recovery_required: bool = False,
    ) -> None:
        if _authority is not _LEASE_AUTHORITY:
            raise HostActivityError("host activity handles require a live gate acquisition")
        self._root = root
        self._identity = identity
        self._exclusive = exclusive
        self._recovery_required = recovery_required
        self._descriptor = descriptor
        self._pid = os.getpid()
        self._active = True

    @property
    def root(self) -> Path:
        return self._root

    @property
    def identity(self) -> HostGateIdentity:
        return self._identity

    @property
    def exclusive(self) -> bool:
        return self._exclusive

    @property
    def recovery_required(self) -> bool:
        return self._recovery_required

    def require_active(self, *, exclusive: bool = False) -> None:
        if not self._active or self._pid != os.getpid() or (exclusive and not self.exclusive):
            raise HostActivityError("host activity handle is not active in the required mode")
        try:
            _root_path(self.root)
            held = os.fstat(self._descriptor)
            named = (self.root / _GATE_FILE).lstat()
            if (
                not stat.S_ISREG(held.st_mode) or not stat.S_ISREG(named.st_mode)
                or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
                or held.st_nlink != 1 or held.st_uid != os.geteuid()
                or held.st_mode & 0o077 or self.root.stat().st_mode & 0o077
            ):
                raise ValueError("gate identity changed")
            raw = read_bounded_regular_bytes(
                self.root / _GATE_FILE, max_bytes=_MAX_GATE_BYTES,
                label="host runtime gate", require_single_link=True,
            )
            if raw != self.identity.canonical():
                raise ValueError("gate contents changed")
        except (OSError, ValueError):
            raise HostActivityError(
                "host activity gate is missing, changed or not private"
            ) from None

    def _close(self) -> None:
        self._active = False
        # Closing the owned descriptor releases its flock. Do not explicitly
        # unlock an inherited descriptor in a forked child.
        os.close(self._descriptor)


@contextmanager
def _locked_gate(
    root: Path, *, inventory_sha256: str, inventory_id: str, exclusive: bool,
    recovery_required: bool = False,
) -> Iterator[HostActivityLease]:
    root = _root_path(root)
    descriptor = -1
    lease: HostActivityLease | None = None
    try:
        raw = read_bounded_regular_bytes(
            root / _GATE_FILE, max_bytes=_MAX_GATE_BYTES,
            label="host runtime gate", require_single_link=True,
        )
        identity = HostGateIdentity.model_validate(parse_strict_json_bytes(
            raw, label="host runtime gate", max_bytes=_MAX_GATE_BYTES,
        ))
        if (
            raw != identity.canonical() or identity.inventory_sha256 != inventory_sha256
            or identity.root_sha256 != host_root_digest(root)
            or identity.inventory_id != inventory_id
        ):
            raise ValueError("gate differs from the expected runtime inventory")
        descriptor = os.open(root / _GATE_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        lease = HostActivityLease(
            root=root, identity=identity, descriptor=descriptor, exclusive=exclusive,
            _authority=_LEASE_AUTHORITY, recovery_required=recovery_required,
        )
        lease.require_active()
    except (OSError, TypeError, ValueError, HostActivityError):
        if descriptor >= 0:
            os.close(descriptor)
        raise HostActivityError(
            "host activity gate is unavailable or has a different inventory"
        ) from None
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    try:
        yield lease
        lease.require_active()
    finally:
        lease._close()


def _configured_root() -> Path | None:
    value = os.environ.get(HOST_ROOT_ENV)
    if value is None:
        return None
    if not value or value != value.strip():
        raise HostActivityError("host runtime root must not be blank")
    return _root_path(Path(value))


@contextmanager
def runtime_activity(
    role: RuntimeRole, *, configuration: object | None = None, injected_runtime: bool = False,
) -> Iterator[HostActivityLease | None]:
    """Verify startup and retain a shared gate through the complete owned activity."""
    component = verify_runtime_inventory(
        role, configuration=configuration, injected_runtime=injected_runtime,
    )
    root = _configured_root()
    if root is None:
        yield None
        return
    if component is None:
        raise HostActivityError("host activity requires a pinned runtime inventory")
    inventory = load_runtime_inventory(
        Path(os.environ[INVENTORY_PATH_ENV]), os.environ[INVENTORY_SHA256_ENV],
    )
    with _locked_gate(
        root, inventory_sha256=os.environ[INVENTORY_SHA256_ENV], exclusive=False,
        inventory_id=inventory.inventory_id,
        recovery_required=inventory.recovery_policy is not None,
    ) as lease:
        token = _ACTIVE.set(lease)
        recovery_token = _RECOVERY_COMPONENT.set(
            component if inventory.recovery_policy is not None else None,
        )
        try:
            if inventory.recovery_policy is not None:
                from pajin.runtime.host_recovery import register_runtime_component

                register_runtime_component(lease, component)
            yield lease
        finally:
            _RECOVERY_COMPONENT.reset(recovery_token)
            _ACTIVE.reset(token)


def recovery_activity() -> tuple[HostActivityLease, RuntimeComponentFingerprint] | None:
    """Return only the current v3 activity; metadata cannot construct this capability."""
    component = _RECOVERY_COMPONENT.get()
    if component is None:
        return None
    lease = _ACTIVE.get()
    if lease is None or lease.root != _configured_root() or lease.exclusive:
        raise HostActivityError("recovery registration requires its live runtime context")
    lease.require_active()
    if lease.identity.inventory_sha256 != os.environ.get(INVENTORY_SHA256_ENV):
        raise HostActivityError("recovery registration cannot change its runtime inventory")
    return lease, component


@contextmanager
def host_work() -> Iterator[None]:
    """Protect embedded Supervisor/urgent work using its admitted runtime context."""
    root = _configured_root()
    if root is None:
        if _ACTIVE.get() is not None:
            raise HostActivityError("active host work cannot remove its configured gate")
        yield
        return
    parent = _ACTIVE.get()
    if (
        parent is None or parent.root != root or parent.exclusive
        or parent.identity.inventory_sha256 != os.environ.get(INVENTORY_SHA256_ENV)
    ):
        raise HostActivityError("enrolled host work requires an admitted runtime context")
    parent.require_active()
    # A child operation retains its own descriptor until it has drained.
    with _locked_gate(
        root, inventory_sha256=parent.identity.inventory_sha256,
        inventory_id=parent.identity.inventory_id, exclusive=False,
        recovery_required=parent.recovery_required,
    ):
        yield


@contextmanager
def host_quiescence(
    root: Path, *, inventory_path: Path, inventory_sha256: str,
) -> Iterator[HostActivityLease]:
    """Exclude participating activities for the entire checkpoint operation.

    This is local writer exclusion, not proof of complete stores, physical
    cleanup, a correct backup, or an independently expected recovery checkpoint.
    """
    inventory = load_runtime_inventory(inventory_path, inventory_sha256)
    if inventory.host_root_sha256 != host_root_digest(root):
        raise HostActivityError("quiescence requires the enrolled inventory host root")
    with _locked_gate(
        root, inventory_sha256=inventory_sha256,
        inventory_id=inventory.inventory_id, exclusive=True,
        recovery_required=inventory.recovery_policy is not None,
    ) as lease:
        yield lease


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("enroll", "check-idle"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "enroll":
            result = enroll_host_gate(
                args.root, inventory_path=args.inventory, inventory_sha256=args.sha256,
            )
        else:
            with host_quiescence(
                args.root, inventory_path=args.inventory, inventory_sha256=args.sha256,
            ) as lease:
                result = lease.identity
        print(result.model_dump_json(by_alias=True))
    except (OSError, RuntimeError, TypeError, ValueError):
        sys.stderr.write("Host activity command failed; no activity was admitted.\n")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
