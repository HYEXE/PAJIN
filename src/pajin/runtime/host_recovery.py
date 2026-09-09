"""First-use store enrollment for the v3 local recovery boundary."""

from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast

from pajin.runtime.host_gate import (
    HostActivityLease,
    HostGateIdentity,
    host_work,
    recovery_activity,
)
from pajin.runtime.host_recovery_models import (
    HostRecoveryInventory,
    RecoveryRegistration,
    recovery_bytes,
)
from pajin.runtime.inventory import RuntimeComponentFingerprint, RuntimeInventory
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.supervision.run_binding import SupervisorRunBinding

_INDEX = "recovery-index.sqlite3"
_APPLICATION_ID = 0x50414852
_MAX_INDEX_BYTES = 8 * 1024 * 1024
_TICKET_AUTHORITY = object()
_TABLES = {
    "recovery_metadata": "CREATE TABLE recovery_metadata ("
    "key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT",
    "recovery_components": "CREATE TABLE recovery_components ("
    "key TEXT PRIMARY KEY, payload TEXT NOT NULL, digest TEXT NOT NULL) STRICT",
    "recovery_registrations": "CREATE TABLE recovery_registrations ("
    "key TEXT PRIMARY KEY, payload TEXT NOT NULL, digest TEXT NOT NULL) STRICT",
}
_SCHEMA = {("table", name): sql for name, sql in _TABLES.items()}
for _table in _TABLES:
    for _operation in ("UPDATE", "DELETE"):
        _name = f"{_table}_no_{_operation.lower()}"
        _SCHEMA[("trigger", _name)] = (
            f"CREATE TRIGGER {_name} BEFORE {_operation} ON {_table} "
            "BEGIN SELECT RAISE(ABORT, 'recovery registration is immutable'); END"
        )
    _name = f"{_table}_no_replace"
    _SCHEMA[("trigger", _name)] = (
        f"CREATE TRIGGER {_name} BEFORE INSERT ON {_table} "
        f"WHEN EXISTS (SELECT 1 FROM {_table} WHERE key = NEW.key OR rowid = NEW.rowid) "
        "BEGIN SELECT RAISE(ABORT, 'recovery registration cannot be replaced'); END"
    )


class RecoveryEnrollmentError(RuntimeError):
    """Required enrollment is missing, changed, incomplete or outside its host."""


def _file_identity(path: Path) -> tuple[int, int]:
    for parent in path.parents:
        if parent.is_symlink() or not parent.is_dir():
            raise RecoveryEnrollmentError("recovery index directory is not regular")
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or info.st_uid != os.geteuid()
        or info.st_size > _MAX_INDEX_BYTES
    ):
        raise RecoveryEnrollmentError("recovery index is not private and regular")
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.is_symlink() or (
            sidecar.exists() and (not sidecar.is_file() or sidecar.stat().st_nlink != 1)
        ):
            raise RecoveryEnrollmentError("recovery index sidecar is invalid")
    return info.st_dev, info.st_ino


def _open(path: Path, *, write: bool) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"{path.as_uri()}?mode={'rw' if write else 'ro'}",
        uri=True,
        timeout=5,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA trusted_schema = OFF")
    connection.execute("PRAGMA foreign_keys = ON")
    if write:
        connection.execute("PRAGMA synchronous = FULL")
    else:
        connection.execute("PRAGMA query_only = ON")
    return connection


def initialize_recovery_index(
    root: Path,
    gate: HostGateIdentity,
    *,
    inventory_bytes: bytes,
) -> None:
    """Called only when enrolling a new v3 gate; never reopen/repair an old index."""
    if sha256(inventory_bytes).hexdigest() != gate.inventory_sha256:
        raise RecoveryEnrollmentError("recovery enrollment runtime inventory changed")
    path = root / _INDEX
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
    connection = _open(path, write=True)
    try:
        connection.execute("BEGIN IMMEDIATE")
        for sql in _SCHEMA.values():
            connection.execute(sql)
        connection.execute(
            "INSERT INTO recovery_metadata(key, value) VALUES ('gate', ?)",
            (gate.canonical().decode(),),
        )
        connection.execute(
            "INSERT INTO recovery_metadata(key, value) VALUES ('runtime_inventory', ?)",
            (inventory_bytes.decode(),),
        )
        connection.execute("PRAGMA user_version = 1")
        connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
        connection.execute("COMMIT")
    finally:
        connection.close()
    _file_identity(path)
    with path.open("rb") as output:
        os.fsync(output.fileno())


def _validate(connection: sqlite3.Connection, gate: HostGateIdentity) -> None:
    observed = {
        (row["type"], row["name"]): " ".join(row["sql"].split())
        for row in connection.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL"
        )
    }
    if (
        observed != {key: " ".join(value.split()) for key, value in _SCHEMA.items()}
        or connection.execute("PRAGMA user_version").fetchone()[0] != 1
        or connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID
        or connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
    ):
        raise RecoveryEnrollmentError("recovery index schema or host identity differs")
    _registered_runtime(connection, gate)


def _registered_runtime(connection: sqlite3.Connection, gate: HostGateIdentity) -> RuntimeInventory:
    metadata = dict(connection.execute("SELECT key, value FROM recovery_metadata"))
    if (
        set(metadata) != {"gate", "runtime_inventory"}
        or metadata["gate"] != gate.canonical().decode()
    ):
        raise RecoveryEnrollmentError("recovery index metadata differs")
    raw = metadata["runtime_inventory"].encode()
    if sha256(raw).hexdigest() != gate.inventory_sha256:
        raise RecoveryEnrollmentError("recovery index runtime inventory differs from its gate")
    runtime = RuntimeInventory.model_validate(
        parse_strict_json_bytes(
            raw,
            label="registered runtime inventory",
            max_bytes=64 * 1024,
        )
    )
    if (
        runtime.recovery_policy != "closed-local-sqlite-v1"
        or runtime.host_root_sha256 != gate.root_sha256
        or runtime.inventory_id != gate.inventory_id
    ):
        raise RecoveryEnrollmentError("recovery index runtime does not own this host gate")
    return runtime


@contextmanager
def _transaction(lease: HostActivityLease, *, write: bool) -> Iterator[sqlite3.Connection]:
    lease.require_active()
    path = lease.root / _INDEX
    identity = _file_identity(path)
    connection = _open(path, write=write)
    try:
        if _file_identity(path) != identity:
            raise RecoveryEnrollmentError("recovery index changed while opening")
        connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        _validate(connection, lease.identity)
        yield connection
        lease.require_active()
        if _file_identity(path) != identity:
            raise RecoveryEnrollmentError("recovery index changed during registration")
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def _insert(
    connection: sqlite3.Connection,
    *,
    table: str,
    key: str,
    payload: bytes,
    maximum: int,
) -> None:
    digest = sha256(payload).hexdigest()
    existing = connection.execute(
        f"SELECT payload, digest FROM {table} WHERE key = ?", (key,)
    ).fetchone()
    if existing is not None:
        if tuple(existing) != (payload.decode(), digest):
            raise RecoveryEnrollmentError("recovery registration differs from its first use")
        return
    if connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] >= maximum:
        raise RecoveryEnrollmentError("recovery registration capacity is exhausted")
    connection.execute(
        f"INSERT INTO {table}(key, payload, digest) VALUES (?, ?, ?)",
        (
            key,
            payload.decode(),
            digest,
        ),
    )


def register_runtime_component(
    lease: HostActivityLease,
    component: RuntimeComponentFingerprint,
) -> None:
    if recovery_activity() != (lease, component):
        raise RecoveryEnrollmentError(
            "component registration requires actual admitted runtime activity"
        )
    with _transaction(lease, write=True) as connection:
        _insert(
            connection,
            table="recovery_components",
            key=component.component_id,
            payload=recovery_bytes(component),
            maximum=64,
        )


def _member_path(root: Path, path: Path) -> str:
    if not path.is_absolute() or ".." in path.parts or not path.is_relative_to(root / "state"):
        raise RecoveryEnrollmentError("registered state must be inside the host state directory")
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RecoveryEnrollmentError("registered state cannot use symbolic links")
    return path.relative_to(root / "state").as_posix()


@dataclass(frozen=True)
class StoreEnrollment:
    """One in-process construction intent, completed before the store is usable."""

    root: Path
    gate: HostGateIdentity
    registration: RecoveryRegistration
    component: RuntimeComponentFingerprint
    authority: object

    def before_open(self) -> None:
        prepared = prepare_store_enrollment(
            self.root / "state" / self.registration.path,
            kind=self.registration.kind,
            campaign_id=self.registration.campaign_id,
            run_id=self.registration.run_id,
            run_binding=self.registration.run_binding,
        )
        if prepared is None or prepared != self:
            raise RecoveryEnrollmentError("store opening changed its enrolled runtime context")

    def complete(self) -> None:
        context = recovery_activity()
        if self.authority is not _TICKET_AUTHORITY or context is None:
            raise RecoveryEnrollmentError("store enrollment requires its live constructing runtime")
        lease, component = context
        if lease.identity != self.gate or component != self.component:
            raise RecoveryEnrollmentError("store enrollment changed its runtime component")
        path = self.root / "state" / self.registration.path
        _member_path(self.root, path)
        if self.registration.kind == "run-store":
            if not path.is_dir():
                raise RecoveryEnrollmentError("registered RunStore was not created")
        elif not path.is_file() or path.stat().st_nlink != 1:
            raise RecoveryEnrollmentError("registered database was not created as a regular file")
        with host_work(), _transaction(lease, write=True) as connection:
            _insert(
                connection,
                table="recovery_registrations",
                key=self.registration.path,
                payload=recovery_bytes(self.registration),
                maximum=4096,
            )


def prepare_store_enrollment(
    path: Path,
    *,
    kind: Literal["control-plane-sqlite", "graph-sqlite", "supervisor-sqlite", "run-store"],
    campaign_id: str | None = None,
    run_id: str | None = None,
    run_binding: SupervisorRunBinding | None = None,
) -> StoreEnrollment | None:
    context = recovery_activity()
    if context is None:
        return None
    lease, component = context
    registration = RecoveryRegistration(
        path=_member_path(lease.root, path),
        kind=kind,
        campaignId=campaign_id,
        runId=run_id,
        runBinding=run_binding,
    )
    with host_work(), _transaction(lease, write=False) as connection:
        row = connection.execute(
            "SELECT payload, digest FROM recovery_registrations WHERE key = ?",
            (registration.path,),
        ).fetchone()
        if row is None:
            if path.exists():
                raise RecoveryEnrollmentError(
                    "existing state has no first-use recovery registration"
                )
        elif tuple(row) != (recovery_bytes(registration).decode(), registration.digest):
            raise RecoveryEnrollmentError("store differs from its first-use recovery binding")
        elif not path.exists():
            raise RecoveryEnrollmentError("registered state is missing; recreation is prohibited")
    return StoreEnrollment(lease.root, lease.identity, registration, component, _TICKET_AUTHORITY)


def prepare_control_plane_enrollment(database_url: str) -> StoreEnrollment | None:
    if recovery_activity() is None:
        return None
    from sqlalchemy.engine import make_url

    url = make_url(database_url)
    if (
        url.get_backend_name() != "sqlite"
        or not url.database
        or url.database == ":memory:"
        or url.query
    ):
        raise RecoveryEnrollmentError(
            "enrolled CP recovery requires a regular local SQLite database"
        )
    return prepare_store_enrollment(
        Path(url.database).absolute(),
        kind="control-plane-sqlite",
    )


def require_recovery_output_root(path: Path) -> None:
    """Validate default Worker output/accounting locations before a new claim."""
    context = recovery_activity()
    if context is not None:
        _member_path(context[0].root, path.absolute())


def inspect_recovery_inventory(
    lease: HostActivityLease,
    *,
    require_complete: bool = False,
) -> HostRecoveryInventory:
    """Read the exact registered set under a live gate without initializing or repairing it."""
    with _transaction(lease, write=False) as connection:
        values: dict[str, list[object]] = {}
        for table in ("recovery_components", "recovery_registrations"):
            values[table] = []
            for row in connection.execute(f"SELECT key, payload, digest FROM {table} ORDER BY key"):
                raw = row["payload"].encode()
                if sha256(raw).hexdigest() != row["digest"]:
                    raise RecoveryEnrollmentError("recovery registration digest differs")
                item = parse_strict_json_bytes(raw, label="recovery registration", max_bytes=8192)
                values[table].append(item)
        result = HostRecoveryInventory.model_validate(
            {
                "gate": lease.identity,
                "components": values["recovery_components"],
                "registrations": values["recovery_registrations"],
            }
        )
        if require_complete and result.components != tuple(
            sorted(
                _registered_runtime(connection, lease.identity).components,
                key=lambda item: item.component_id,
            )
        ):
            raise RecoveryEnrollmentError("not every configured runtime participant has registered")
        for table, items in (
            ("recovery_components", result.components),
            ("recovery_registrations", result.registrations),
        ):
            for item, row in zip(
                items,
                connection.execute(
                    f"SELECT key, payload FROM {table} ORDER BY key",
                ),
                strict=True,
            ):
                key = (
                    item.component_id
                    if isinstance(item, RuntimeComponentFingerprint)
                    else (cast(RecoveryRegistration, item).path)
                )
                if row["key"] != key or row["payload"].encode() != recovery_bytes(item):
                    raise RecoveryEnrollmentError("recovery registration index differs")
        return result
