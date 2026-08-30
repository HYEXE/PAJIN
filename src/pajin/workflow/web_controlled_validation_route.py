"""Durable one-shot claims for controlled web-validation routes."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.models import benchmark_digest
from pajin.domain.models import StrictModel

WEB_CONTROLLED_VALIDATION_ROUTE_CLAIM_RECEIPT_API_VERSION: Literal[
    "pajin.dev/web-controlled-validation-route-claim-receipt/v1alpha1"
] = "pajin.dev/web-controlled-validation-route-claim-receipt/v1alpha1"
WEB_CONTROLLED_VALIDATION_ROUTE_CLAIM_RECEIPT_KIND: Literal[
    "WebControlledValidationRouteClaimReceipt"
] = "WebControlledValidationRouteClaimReceipt"
WEB_CONTROLLED_VALIDATION_ROUTE_DENIAL_RECEIPT_API_VERSION: Literal[
    "pajin.dev/web-controlled-validation-route-denial-receipt/v1alpha1"
] = "pajin.dev/web-controlled-validation-route-denial-receipt/v1alpha1"
WEB_CONTROLLED_VALIDATION_ROUTE_DENIAL_RECEIPT_KIND: Literal[
    "WebControlledValidationRouteDenialReceipt"
] = "WebControlledValidationRouteDenialReceipt"

_RECEIPT_DIGEST_DOMAIN = "pajin.workflow.web-controlled-validation-route-claim-receipt/v1"
_DENIAL_RECEIPT_DIGEST_DOMAIN = "pajin.workflow.web-controlled-validation-route-denial-receipt/v1"
_LEDGER_IDENTITY_DIGEST_DOMAIN = (
    "pajin.workflow.web-controlled-validation-route-claim-ledger-identity/v1"
)
_MAX_RECEIPT_BYTES = 64 * 1024
_BUSY_TIMEOUT_MS = 5_000
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]

_TABLE_NAME = "web_controlled_validation_route_claims"
_DENIAL_TABLE_NAME = "web_controlled_validation_route_denials"
_TABLE_STATEMENTS = {
    _TABLE_NAME: f"""
    CREATE TABLE {_TABLE_NAME} (
        slot_digest TEXT PRIMARY KEY,
        route_digest TEXT NOT NULL UNIQUE,
        verification_digest TEXT NOT NULL UNIQUE,
        claimed_at TEXT NOT NULL,
        receipt_digest TEXT NOT NULL UNIQUE,
        receipt_json TEXT NOT NULL
    )
    """,
    _DENIAL_TABLE_NAME: f"""
    CREATE TABLE {_DENIAL_TABLE_NAME} (
        slot_digest TEXT PRIMARY KEY,
        route_digest TEXT NOT NULL UNIQUE,
        denied_at TEXT NOT NULL,
        receipt_digest TEXT NOT NULL UNIQUE,
        receipt_json TEXT NOT NULL
    )
    """,
}
_CLAIM_TRIGGER_STATEMENTS = {
    f"{_TABLE_NAME}_no_update": f"""
    CREATE TRIGGER IF NOT EXISTS {_TABLE_NAME}_no_update
    BEFORE UPDATE ON {_TABLE_NAME}
    BEGIN
        SELECT RAISE(ABORT, 'web controlled validation route claims are append-only');
    END
    """,
    f"{_TABLE_NAME}_no_delete": f"""
    CREATE TRIGGER IF NOT EXISTS {_TABLE_NAME}_no_delete
    BEFORE DELETE ON {_TABLE_NAME}
    BEGIN
        SELECT RAISE(ABORT, 'web controlled validation route claims are append-only');
    END
    """,
    f"{_TABLE_NAME}_no_replace": f"""
    CREATE TRIGGER IF NOT EXISTS {_TABLE_NAME}_no_replace
    BEFORE INSERT ON {_TABLE_NAME}
    WHEN EXISTS (
        SELECT 1
        FROM {_TABLE_NAME}
        WHERE slot_digest = NEW.slot_digest
           OR route_digest = NEW.route_digest
           OR verification_digest = NEW.verification_digest
           OR receipt_digest = NEW.receipt_digest
    )
    BEGIN
        SELECT RAISE(ABORT, 'web controlled validation route claim cannot be replaced');
    END
    """,
    f"{_TABLE_NAME}_denial_guard": f"""
    CREATE TRIGGER IF NOT EXISTS {_TABLE_NAME}_denial_guard
    BEFORE INSERT ON {_TABLE_NAME}
    WHEN EXISTS (
        SELECT 1
        FROM {_DENIAL_TABLE_NAME}
        WHERE slot_digest = NEW.slot_digest
           OR route_digest = NEW.route_digest
    )
    BEGIN
        SELECT RAISE(ABORT, 'web controlled validation route is durably denied');
    END
    """,
}
_DENIAL_TRIGGER_STATEMENTS = {
    f"{_DENIAL_TABLE_NAME}_no_update": f"""
    CREATE TRIGGER IF NOT EXISTS {_DENIAL_TABLE_NAME}_no_update
    BEFORE UPDATE ON {_DENIAL_TABLE_NAME}
    BEGIN
        SELECT RAISE(ABORT, 'web controlled validation route denials are append-only');
    END
    """,
    f"{_DENIAL_TABLE_NAME}_no_delete": f"""
    CREATE TRIGGER IF NOT EXISTS {_DENIAL_TABLE_NAME}_no_delete
    BEFORE DELETE ON {_DENIAL_TABLE_NAME}
    BEGIN
        SELECT RAISE(ABORT, 'web controlled validation route denials are append-only');
    END
    """,
    f"{_DENIAL_TABLE_NAME}_no_replace": f"""
    CREATE TRIGGER IF NOT EXISTS {_DENIAL_TABLE_NAME}_no_replace
    BEFORE INSERT ON {_DENIAL_TABLE_NAME}
    WHEN EXISTS (
        SELECT 1
        FROM {_DENIAL_TABLE_NAME}
        WHERE slot_digest = NEW.slot_digest
           OR route_digest = NEW.route_digest
           OR receipt_digest = NEW.receipt_digest
    )
    BEGIN
        SELECT RAISE(ABORT, 'web controlled validation route denial cannot be replaced');
    END
    """,
    f"{_DENIAL_TABLE_NAME}_claim_guard": f"""
    CREATE TRIGGER IF NOT EXISTS {_DENIAL_TABLE_NAME}_claim_guard
    BEFORE INSERT ON {_DENIAL_TABLE_NAME}
    WHEN EXISTS (
        SELECT 1
        FROM {_TABLE_NAME}
        WHERE slot_digest = NEW.slot_digest
           OR route_digest = NEW.route_digest
    )
    BEGIN
        SELECT RAISE(ABORT, 'web controlled validation route is already claimed');
    END
    """,
}
_TRIGGER_STATEMENTS = (
    *_CLAIM_TRIGGER_STATEMENTS.values(),
    *_DENIAL_TRIGGER_STATEMENTS.values(),
)
_CLAIM_TRIGGER_NAMES = frozenset(_CLAIM_TRIGGER_STATEMENTS)
_DENIAL_TRIGGER_NAMES = frozenset(_DENIAL_TRIGGER_STATEMENTS)
_INDEX_NAMES = frozenset(
    {
        f"sqlite_autoindex_{_TABLE_NAME}_1",
        f"sqlite_autoindex_{_TABLE_NAME}_2",
        f"sqlite_autoindex_{_TABLE_NAME}_3",
        f"sqlite_autoindex_{_TABLE_NAME}_4",
        f"sqlite_autoindex_{_DENIAL_TABLE_NAME}_1",
        f"sqlite_autoindex_{_DENIAL_TABLE_NAME}_2",
        f"sqlite_autoindex_{_DENIAL_TABLE_NAME}_3",
    }
)
_ROW_FIELDS = (
    "slot_digest",
    "route_digest",
    "verification_digest",
    "claimed_at",
    "receipt_digest",
    "receipt_json",
)
_SELECT_RECEIPT = f"SELECT {', '.join(_ROW_FIELDS)} FROM {_TABLE_NAME}"
_DENIAL_ROW_FIELDS = (
    "slot_digest",
    "route_digest",
    "denied_at",
    "receipt_digest",
    "receipt_json",
)
_SELECT_DENIAL_RECEIPT = f"SELECT {', '.join(_DENIAL_ROW_FIELDS)} FROM {_DENIAL_TABLE_NAME}"


class WebControlledValidationRouteClaimError(RuntimeError):
    """Raised when a durable controlled-validation route claim is invalid or conflicts."""


class WebControlledValidationRouteClaimReceipt(StrictModel):
    """Content-addressed proof that one validation slot claimed one signed route."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    api_version: Literal["pajin.dev/web-controlled-validation-route-claim-receipt/v1alpha1"] = (
        Field(
            default=WEB_CONTROLLED_VALIDATION_ROUTE_CLAIM_RECEIPT_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["WebControlledValidationRouteClaimReceipt"] = Field(
        default=WEB_CONTROLLED_VALIDATION_ROUTE_CLAIM_RECEIPT_KIND
    )
    slot_digest: _Sha256 = Field(alias="slotDigest")
    route_digest: _Sha256 = Field(alias="routeDigest")
    verification_digest: _Sha256 = Field(alias="verificationDigest")
    claimed_at: datetime = Field(alias="claimedAt")
    receipt_digest: _Sha256 = Field(default="", alias="receiptDigest")

    @field_validator("claimed_at")
    @classmethod
    def _normalize_claimed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("claimedAt must include a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _derive_receipt_digest(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_digest"},
        )
        computed = benchmark_digest(
            _RECEIPT_DIGEST_DOMAIN,
            material,
            max_bytes=_MAX_RECEIPT_BYTES,
        )
        if self.receipt_digest and self.receipt_digest != computed:
            raise ValueError("receiptDigest does not match the canonical receipt")
        object.__setattr__(self, "receipt_digest", computed)
        return self


class WebControlledValidationRouteDenialReceipt(StrictModel):
    """Append-only terminal proof that one unclaimed signed route was denied."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    api_version: Literal["pajin.dev/web-controlled-validation-route-denial-receipt/v1alpha1"] = (
        Field(
            default=WEB_CONTROLLED_VALIDATION_ROUTE_DENIAL_RECEIPT_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["WebControlledValidationRouteDenialReceipt"] = Field(
        default=WEB_CONTROLLED_VALIDATION_ROUTE_DENIAL_RECEIPT_KIND
    )
    slot_digest: _Sha256 = Field(alias="slotDigest")
    route_digest: _Sha256 = Field(alias="routeDigest")
    denied_at: datetime = Field(alias="deniedAt")
    receipt_digest: _Sha256 = Field(default="", alias="receiptDigest")

    @field_validator("denied_at")
    @classmethod
    def _normalize_denied_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("deniedAt must include a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _derive_receipt_digest(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_digest"},
        )
        computed = benchmark_digest(
            _DENIAL_RECEIPT_DIGEST_DOMAIN,
            material,
            max_bytes=_MAX_RECEIPT_BYTES,
        )
        if self.receipt_digest and self.receipt_digest != computed:
            raise ValueError("receiptDigest does not match the canonical denial receipt")
        object.__setattr__(self, "receipt_digest", computed)
        return self


class WebControlledValidationRouteClaimLedger:
    """SQLite-backed compare-and-set ledger for one-shot route authority."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))
        self._initialize()

    def identity_digest(self, *, deployment_id: str) -> str:
        """Return the opaque deployment/path identity signed into route policy."""

        self._require_safe_path()
        return web_controlled_validation_route_claim_ledger_identity_digest(
            self.path,
            deployment_id=deployment_id,
        )

    def claim_once(
        self,
        *,
        slot_digest: str,
        route_digest: str,
        verification_digest: str,
        claimed_at: datetime,
    ) -> WebControlledValidationRouteClaimReceipt:
        """Claim a route exactly once before validation side effects."""

        candidate = _build_receipt(
            slot_digest=slot_digest,
            route_digest=route_digest,
            verification_digest=verification_digest,
            claimed_at=claimed_at,
        )
        with self._write_transaction() as connection:
            denied = connection.execute(
                f"""{_SELECT_DENIAL_RECEIPT}
                WHERE slot_digest = ? OR route_digest = ?""",
                (candidate.slot_digest, candidate.route_digest),
            ).fetchone()
            if denied is not None:
                _denial_receipt_from_row(denied)
                raise WebControlledValidationRouteClaimError(
                    "the validation route or slot is durably denied"
                )
            row = connection.execute(
                f"{_SELECT_RECEIPT} WHERE slot_digest = ?",
                (candidate.slot_digest,),
            ).fetchone()
            if row is not None:
                _receipt_from_row(row)
                raise WebControlledValidationRouteClaimError(
                    "the validation slot has already been consumed"
                )

            conflicting = connection.execute(
                f"""{_SELECT_RECEIPT}
                WHERE route_digest = ?
                   OR verification_digest = ?
                   OR receipt_digest = ?""",
                (
                    candidate.route_digest,
                    candidate.verification_digest,
                    candidate.receipt_digest,
                ),
            ).fetchone()
            if conflicting is not None:
                _receipt_from_row(conflicting)
                raise WebControlledValidationRouteClaimError(
                    "the signed route or its verification is already bound to another slot"
                )

            receipt_json = candidate.model_dump_json(by_alias=True)
            try:
                connection.execute(
                    f"""INSERT INTO {_TABLE_NAME} (
                        slot_digest,
                        route_digest,
                        verification_digest,
                        claimed_at,
                        receipt_digest,
                        receipt_json
                    ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        candidate.slot_digest,
                        candidate.route_digest,
                        candidate.verification_digest,
                        candidate.claimed_at.isoformat(),
                        candidate.receipt_digest,
                        receipt_json,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise WebControlledValidationRouteClaimError(
                    "the validation route claim conflicts with an existing durable claim"
                ) from error

            inserted = connection.execute(
                f"{_SELECT_RECEIPT} WHERE slot_digest = ?",
                (candidate.slot_digest,),
            ).fetchone()
            if inserted is None:
                raise WebControlledValidationRouteClaimError(
                    "the validation route claim was not durably recorded"
                )
            stored = _receipt_from_row(inserted)
            if stored != candidate:
                raise WebControlledValidationRouteClaimError(
                    "the durable validation route claim does not match its candidate"
                )
            return stored.model_copy(deep=True)

    def seal_denial_if_unclaimed(
        self,
        *,
        slot_digest: str,
        route_digest: str,
        denied_at: datetime,
    ) -> WebControlledValidationRouteDenialReceipt:
        """Atomically seal an unclaimed route as denied, allowing only exact retries."""

        candidate = _build_denial_receipt(
            slot_digest=slot_digest,
            route_digest=route_digest,
            denied_at=denied_at,
        )
        with self._write_transaction() as connection:
            claimed = connection.execute(
                f"""{_SELECT_RECEIPT}
                WHERE slot_digest = ? OR route_digest = ?""",
                (candidate.slot_digest, candidate.route_digest),
            ).fetchone()
            if claimed is not None:
                _receipt_from_row(claimed)
                raise WebControlledValidationRouteClaimError(
                    "the validation route or slot has already been claimed"
                )

            existing = connection.execute(
                f"{_SELECT_DENIAL_RECEIPT} WHERE slot_digest = ?",
                (candidate.slot_digest,),
            ).fetchone()
            if existing is not None:
                stored = _denial_receipt_from_row(existing)
                if stored == candidate:
                    return stored.model_copy(deep=True)
                raise WebControlledValidationRouteClaimError(
                    "the validation slot is already bound to a different denial"
                )

            conflicting = connection.execute(
                f"""{_SELECT_DENIAL_RECEIPT}
                WHERE route_digest = ? OR receipt_digest = ?""",
                (candidate.route_digest, candidate.receipt_digest),
            ).fetchone()
            if conflicting is not None:
                _denial_receipt_from_row(conflicting)
                raise WebControlledValidationRouteClaimError(
                    "the signed route is already bound to another denial slot"
                )

            receipt_json = candidate.model_dump_json(by_alias=True)
            try:
                connection.execute(
                    f"""INSERT INTO {_DENIAL_TABLE_NAME} (
                        slot_digest,
                        route_digest,
                        denied_at,
                        receipt_digest,
                        receipt_json
                    ) VALUES (?, ?, ?, ?, ?)""",
                    (
                        candidate.slot_digest,
                        candidate.route_digest,
                        candidate.denied_at.isoformat(),
                        candidate.receipt_digest,
                        receipt_json,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise WebControlledValidationRouteClaimError(
                    "the validation route denial conflicts with durable state"
                ) from error

            inserted = connection.execute(
                f"{_SELECT_DENIAL_RECEIPT} WHERE slot_digest = ?",
                (candidate.slot_digest,),
            ).fetchone()
            if inserted is None:
                raise WebControlledValidationRouteClaimError(
                    "the validation route denial was not durably recorded"
                )
            stored = _denial_receipt_from_row(inserted)
            if stored != candidate:
                raise WebControlledValidationRouteClaimError(
                    "the durable validation route denial differs from its candidate"
                )
            return stored.model_copy(deep=True)

    def require_unclaimed(self, *, slot_digest: str, route_digest: str) -> None:
        """Prove through durable read-only state that neither route identity was claimed."""

        for label, value in (("slot", slot_digest), ("route", route_digest)):
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise WebControlledValidationRouteClaimError(
                    f"the validation {label} digest is invalid"
                )
        with self._read_transaction() as connection:
            rows = connection.execute(
                f"{_SELECT_RECEIPT} WHERE slot_digest = ? OR route_digest = ?",
                (slot_digest, route_digest),
            ).fetchall()
            for row in rows:
                _receipt_from_row(row)
        if rows:
            raise WebControlledValidationRouteClaimError(
                "the validation route or slot has already been claimed"
            )

    def _load(self, slot_digest: str) -> WebControlledValidationRouteClaimReceipt | None:
        with self._read_transaction() as connection:
            row = connection.execute(
                f"{_SELECT_RECEIPT} WHERE slot_digest = ?",
                (slot_digest,),
            ).fetchone()
            if row is None:
                return None
            return _receipt_from_row(row).model_copy(deep=True)

    def _load_denial(
        self,
        slot_digest: str,
    ) -> WebControlledValidationRouteDenialReceipt | None:
        with self._read_transaction() as connection:
            row = connection.execute(
                f"{_SELECT_DENIAL_RECEIPT} WHERE slot_digest = ?",
                (slot_digest,),
            ).fetchone()
            if row is None:
                return None
            return _denial_receipt_from_row(row).model_copy(deep=True)

    def _initialize(self) -> None:
        self._require_safe_path(allow_missing_parent=True)
        self._require_safe_sidecars()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._require_safe_path()
        self._require_safe_sidecars()
        created = self._create_exclusive_store_file()
        self._require_safe_path()
        self._require_safe_sidecars()
        if not created:
            self._validate_existing_store()
            return

        connection = self._open_write_connection()
        try:
            journal_mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if journal_mode is None or str(journal_mode[0]).lower() != "delete":
                raise WebControlledValidationRouteClaimError(
                    "route claim ledger must use SQLite DELETE journal mode"
                )
            connection.execute("BEGIN IMMEDIATE")
            for statement in _TABLE_STATEMENTS.values():
                connection.execute(statement)
            for statement in _TRIGGER_STATEMENTS:
                connection.execute(statement)
            _require_ledger_contract(connection)
            connection.commit()
        except WebControlledValidationRouteClaimError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise WebControlledValidationRouteClaimError(
                "could not initialize the validation route claim ledger"
            ) from error
        finally:
            connection.close()
        try:
            self.path.chmod(0o600)
        except OSError as error:
            raise WebControlledValidationRouteClaimError(
                "could not restrict the validation route claim ledger permissions"
            ) from error
        self._require_safe_path()
        self._require_safe_sidecars()

    def _create_exclusive_store_file(self) -> bool:
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError:
            return False
        except OSError as error:
            raise WebControlledValidationRouteClaimError(
                "could not exclusively create the validation route claim ledger"
            ) from error
        try:
            os.close(descriptor)
        except OSError as error:
            raise WebControlledValidationRouteClaimError(
                "could not close the new validation route claim ledger"
            ) from error
        return True

    def _validate_existing_store(self) -> None:
        connection = self._open_write_connection()
        try:
            connection.execute("BEGIN")
            _require_ledger_contract(connection)
            connection.rollback()
        except WebControlledValidationRouteClaimError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise WebControlledValidationRouteClaimError(
                "could not validate the existing validation route claim ledger"
            ) from error
        finally:
            connection.close()
        self._require_safe_path()
        self._require_safe_sidecars()

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        self._require_safe_path()
        self._require_safe_sidecars()
        connection = self._open_write_connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_ledger_contract(connection)
            yield connection
            connection.commit()
        except WebControlledValidationRouteClaimError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise WebControlledValidationRouteClaimError(
                "the validation route claim transaction failed"
            ) from error
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
            self._require_safe_path()
            self._require_safe_sidecars()

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        self._require_safe_path()
        self._require_safe_sidecars()
        try:
            connection = sqlite3.connect(
                f"file:{self.path.as_posix()}?mode=ro",
                uri=True,
                isolation_level=None,
                timeout=_BUSY_TIMEOUT_MS / 1_000,
            )
        except sqlite3.Error as error:
            raise WebControlledValidationRouteClaimError(
                "could not open the validation route claim ledger read-only"
            ) from error
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            _require_ledger_contract(connection)
            yield connection
        except WebControlledValidationRouteClaimError:
            raise
        except sqlite3.Error as error:
            raise WebControlledValidationRouteClaimError(
                "the validation route claim read failed"
            ) from error
        finally:
            connection.rollback()
            connection.close()
            self._require_safe_path()
            self._require_safe_sidecars()

    def _open_write_connection(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"file:{self.path.as_posix()}?mode=rw",
                uri=True,
                isolation_level=None,
                timeout=_BUSY_TIMEOUT_MS / 1_000,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as error:
            if connection is not None:
                connection.close()
            raise WebControlledValidationRouteClaimError(
                "could not open the validation route claim ledger"
            ) from error

    def _require_safe_path(self, *, allow_missing_parent: bool = False) -> None:
        for parent in (self.path.parent, *self.path.parent.parents):
            if parent.is_symlink() or parent.is_junction():
                raise WebControlledValidationRouteClaimError(
                    "route claim ledger parent paths must not be links or junctions"
                )
            if parent.exists() and not parent.is_dir():
                raise WebControlledValidationRouteClaimError(
                    "route claim ledger ancestors must be directories"
                )
        if not allow_missing_parent and not self.path.parent.is_dir():
            raise WebControlledValidationRouteClaimError(
                "route claim ledger parent must be a directory"
            )
        if self.path.is_symlink() or self.path.is_junction():
            raise WebControlledValidationRouteClaimError(
                "route claim ledger must be a regular non-link file"
            )
        if not self.path.exists():
            return
        if not self.path.is_file():
            raise WebControlledValidationRouteClaimError(
                "route claim ledger must be a regular non-link file"
            )
        if self.path.stat().st_nlink != 1:
            raise WebControlledValidationRouteClaimError(
                "route claim ledger must have exactly one filesystem link"
            )

    def _require_safe_sidecars(self) -> None:
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            if sidecar.is_symlink() or sidecar.is_junction():
                raise WebControlledValidationRouteClaimError(
                    "route claim ledger sidecars must be regular non-link files"
                )
            if not sidecar.exists():
                continue
            if not sidecar.is_file():
                raise WebControlledValidationRouteClaimError(
                    "route claim ledger sidecars must be regular non-link files"
                )
            if sidecar.stat().st_nlink != 1:
                raise WebControlledValidationRouteClaimError(
                    "route claim ledger sidecars must have exactly one filesystem link"
                )


def web_controlled_validation_route_claim_ledger_identity_digest(
    path: Path,
    *,
    deployment_id: str,
) -> str:
    """Bind one deployment to one canonical claim-ledger location without exposing it."""

    if (
        type(deployment_id) is not str
        or not deployment_id
        or deployment_id.strip() != deployment_id
    ):
        raise WebControlledValidationRouteClaimError(
            "route claim ledger deployment identity is invalid"
        )
    try:
        normalized_path = os.path.normcase(os.path.normpath(os.path.abspath(path)))
    except (OSError, TypeError, ValueError) as error:
        raise WebControlledValidationRouteClaimError(
            "route claim ledger path identity is invalid"
        ) from error
    return benchmark_digest(
        _LEDGER_IDENTITY_DIGEST_DOMAIN,
        {
            "deploymentId": deployment_id,
            "canonicalPath": normalized_path.replace("\\", "/"),
        },
        max_bytes=64 * 1024,
    )


def load_web_controlled_validation_route_claim_receipt(
    *,
    ledger: WebControlledValidationRouteClaimLedger,
    receipt: WebControlledValidationRouteClaimReceipt,
) -> WebControlledValidationRouteClaimReceipt:
    """Reload and revalidate a receipt from the ledger through a read-only connection."""

    if type(ledger) is not WebControlledValidationRouteClaimLedger:
        raise WebControlledValidationRouteClaimError(
            "ledger must be an exact WebControlledValidationRouteClaimLedger"
        )
    canonical = _canonical_receipt(receipt)
    stored = ledger._load(canonical.slot_digest)
    if stored is None:
        raise WebControlledValidationRouteClaimError(
            "the validation route claim receipt is not present in the ledger"
        )
    if stored != canonical:
        raise WebControlledValidationRouteClaimError(
            "the supplied validation route claim receipt does not match durable state"
        )
    return stored.model_copy(deep=True)


def load_web_controlled_validation_route_denial_receipt(
    *,
    ledger: WebControlledValidationRouteClaimLedger,
    receipt: WebControlledValidationRouteDenialReceipt,
) -> WebControlledValidationRouteDenialReceipt:
    """Reload one terminal denial receipt from exact append-only ledger state."""

    if type(ledger) is not WebControlledValidationRouteClaimLedger:
        raise WebControlledValidationRouteClaimError(
            "ledger must be an exact WebControlledValidationRouteClaimLedger"
        )
    canonical = _canonical_denial_receipt(receipt)
    stored = ledger._load_denial(canonical.slot_digest)
    if stored is None:
        raise WebControlledValidationRouteClaimError(
            "the validation route denial receipt is not present in the ledger"
        )
    if stored != canonical:
        raise WebControlledValidationRouteClaimError(
            "the supplied validation route denial receipt differs from durable state"
        )
    return stored.model_copy(deep=True)


def _build_receipt(
    *,
    slot_digest: str,
    route_digest: str,
    verification_digest: str,
    claimed_at: datetime,
) -> WebControlledValidationRouteClaimReceipt:
    try:
        return WebControlledValidationRouteClaimReceipt(
            slotDigest=slot_digest,
            routeDigest=route_digest,
            verificationDigest=verification_digest,
            claimedAt=claimed_at,
        )
    except (TypeError, ValidationError, ValueError) as error:
        raise WebControlledValidationRouteClaimError(
            "the validation route claim inputs are invalid"
        ) from error


def _build_denial_receipt(
    *,
    slot_digest: str,
    route_digest: str,
    denied_at: datetime,
) -> WebControlledValidationRouteDenialReceipt:
    try:
        return WebControlledValidationRouteDenialReceipt(
            slotDigest=slot_digest,
            routeDigest=route_digest,
            deniedAt=denied_at,
        )
    except (TypeError, ValidationError, ValueError) as error:
        raise WebControlledValidationRouteClaimError(
            "the validation route denial inputs are invalid"
        ) from error


def _canonical_receipt(
    receipt: WebControlledValidationRouteClaimReceipt,
) -> WebControlledValidationRouteClaimReceipt:
    if type(receipt) is not WebControlledValidationRouteClaimReceipt:
        raise WebControlledValidationRouteClaimError(
            "receipt must be an exact WebControlledValidationRouteClaimReceipt"
        )
    expected_fields = frozenset(WebControlledValidationRouteClaimReceipt.model_fields)
    if frozenset(receipt.__dict__) != expected_fields:
        raise WebControlledValidationRouteClaimError(
            "receipt contains hidden or missing model state"
        )
    try:
        canonical = WebControlledValidationRouteClaimReceipt.model_validate(
            receipt.model_dump(mode="python", by_alias=True)
        )
    except (TypeError, ValidationError, ValueError) as error:
        raise WebControlledValidationRouteClaimError("receipt is not canonically valid") from error
    if canonical != receipt:
        raise WebControlledValidationRouteClaimError(
            "receipt differs from its canonical representation"
        )
    return canonical


def _canonical_denial_receipt(
    receipt: WebControlledValidationRouteDenialReceipt,
) -> WebControlledValidationRouteDenialReceipt:
    if type(receipt) is not WebControlledValidationRouteDenialReceipt:
        raise WebControlledValidationRouteClaimError(
            "denial receipt must be an exact WebControlledValidationRouteDenialReceipt"
        )
    expected_fields = frozenset(WebControlledValidationRouteDenialReceipt.model_fields)
    if frozenset(receipt.__dict__) != expected_fields:
        raise WebControlledValidationRouteClaimError(
            "denial receipt contains hidden or missing model state"
        )
    try:
        canonical = WebControlledValidationRouteDenialReceipt.model_validate(
            receipt.model_dump(mode="python", by_alias=True)
        )
    except (TypeError, ValidationError, ValueError) as error:
        raise WebControlledValidationRouteClaimError(
            "denial receipt is not canonically valid"
        ) from error
    if canonical != receipt:
        raise WebControlledValidationRouteClaimError(
            "denial receipt differs from its canonical representation"
        )
    return canonical


def _receipt_from_row(row: sqlite3.Row) -> WebControlledValidationRouteClaimReceipt:
    if tuple(row.keys()) != _ROW_FIELDS:
        raise WebControlledValidationRouteClaimError(
            "route claim ledger row has an unexpected shape"
        )
    values = {field: row[field] for field in _ROW_FIELDS}
    if any(type(value) is not str for value in values.values()):
        raise WebControlledValidationRouteClaimError(
            "route claim ledger row fields must all be text"
        )
    receipt_json = values["receipt_json"]
    try:
        receipt = WebControlledValidationRouteClaimReceipt.model_validate_json(receipt_json)
    except (TypeError, ValidationError, ValueError) as error:
        raise WebControlledValidationRouteClaimError(
            "route claim ledger JSON is not a valid canonical receipt"
        ) from error
    canonical = _canonical_receipt(receipt)
    if canonical.model_dump_json(by_alias=True) != receipt_json:
        raise WebControlledValidationRouteClaimError(
            "route claim ledger JSON is not canonically encoded"
        )
    expected_columns = {
        "slot_digest": canonical.slot_digest,
        "route_digest": canonical.route_digest,
        "verification_digest": canonical.verification_digest,
        "claimed_at": canonical.claimed_at.isoformat(),
        "receipt_digest": canonical.receipt_digest,
    }
    for column, expected in expected_columns.items():
        if values[column] != expected:
            raise WebControlledValidationRouteClaimError(
                f"route claim ledger {column} does not match its canonical receipt"
            )
    return canonical


def _denial_receipt_from_row(
    row: sqlite3.Row,
) -> WebControlledValidationRouteDenialReceipt:
    if tuple(row.keys()) != _DENIAL_ROW_FIELDS:
        raise WebControlledValidationRouteClaimError(
            "route denial ledger row has an unexpected shape"
        )
    values = {field: row[field] for field in _DENIAL_ROW_FIELDS}
    if any(type(value) is not str for value in values.values()):
        raise WebControlledValidationRouteClaimError(
            "route denial ledger row fields must all be text"
        )
    receipt_json = values["receipt_json"]
    try:
        receipt = WebControlledValidationRouteDenialReceipt.model_validate_json(receipt_json)
    except (TypeError, ValidationError, ValueError) as error:
        raise WebControlledValidationRouteClaimError(
            "route denial ledger JSON is not a valid canonical receipt"
        ) from error
    canonical = _canonical_denial_receipt(receipt)
    if canonical.model_dump_json(by_alias=True) != receipt_json:
        raise WebControlledValidationRouteClaimError(
            "route denial ledger JSON is not canonically encoded"
        )
    expected_columns = {
        "slot_digest": canonical.slot_digest,
        "route_digest": canonical.route_digest,
        "denied_at": canonical.denied_at.isoformat(),
        "receipt_digest": canonical.receipt_digest,
    }
    for column, expected in expected_columns.items():
        if values[column] != expected:
            raise WebControlledValidationRouteClaimError(
                f"route denial ledger {column} does not match its canonical receipt"
            )
    return canonical


def _require_ledger_contract(connection: sqlite3.Connection) -> None:
    _require_storage_contract(connection)
    _require_claim_schema(connection)
    _require_denial_schema(connection)
    _require_trigger_contract(
        connection,
        table_name=_TABLE_NAME,
        expected_statements=_CLAIM_TRIGGER_STATEMENTS,
    )
    _require_trigger_contract(
        connection,
        table_name=_DENIAL_TABLE_NAME,
        expected_statements=_DENIAL_TRIGGER_STATEMENTS,
    )
    _require_schema_object_contract(connection)


def _require_storage_contract(connection: sqlite3.Connection) -> None:
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    if (
        journal_mode is None
        or len(journal_mode) != 1
        or type(journal_mode[0]) is not str
        or journal_mode[0].lower() != "delete"
    ):
        raise WebControlledValidationRouteClaimError(
            "route claim ledger must use SQLite DELETE journal mode"
        )
    quick_check = tuple(tuple(row) for row in connection.execute("PRAGMA quick_check"))
    if quick_check != (("ok",),):
        raise WebControlledValidationRouteClaimError("route claim ledger failed SQLite quick_check")


def _require_schema_object_contract(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE type IN ('table', 'index', 'view', 'trigger') ORDER BY type, name"
    ).fetchall()
    observed: dict[tuple[str, str], tuple[str, str | None]] = {}
    for row in rows:
        object_type, name, table_name, statement = row
        if (
            type(object_type) is not str
            or type(name) is not str
            or type(table_name) is not str
            or (statement is not None and type(statement) is not str)
            or (object_type, name) in observed
        ):
            raise WebControlledValidationRouteClaimError(
                "route claim ledger schema-object metadata is invalid"
            )
        observed[(object_type, name)] = (
            table_name,
            None if statement is None else _normalize_schema_sql(statement),
        )

    expected: dict[tuple[str, str], tuple[str, str | None]] = {}
    for table_name, statement in _TABLE_STATEMENTS.items():
        expected[("table", table_name)] = (
            table_name,
            _normalize_schema_sql(statement),
        )
    for index_name in _INDEX_NAMES:
        table_name = _DENIAL_TABLE_NAME if _DENIAL_TABLE_NAME in index_name else _TABLE_NAME
        expected[("index", index_name)] = (table_name, None)
    for trigger_name, statement in {
        **_CLAIM_TRIGGER_STATEMENTS,
        **_DENIAL_TRIGGER_STATEMENTS,
    }.items():
        table_name = _DENIAL_TABLE_NAME if trigger_name in _DENIAL_TRIGGER_NAMES else _TABLE_NAME
        expected[("trigger", trigger_name)] = (
            table_name,
            _normalize_schema_sql(statement),
        )
    if observed != expected:
        raise WebControlledValidationRouteClaimError(
            "route claim ledger schema objects do not match the sealed contract"
        )


def _require_trigger_contract(
    connection: sqlite3.Connection,
    *,
    table_name: str,
    expected_statements: dict[str, str],
) -> None:
    rows = connection.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?",
        (table_name,),
    ).fetchall()
    observed: dict[str, str] = {}
    for row in rows:
        name, statement = row
        if type(name) is not str or type(statement) is not str or name in observed:
            raise WebControlledValidationRouteClaimError(
                "route claim ledger trigger metadata is invalid"
            )
        observed[name] = _normalize_trigger_sql(statement)
    expected = {
        name: _normalize_trigger_sql(statement) for name, statement in expected_statements.items()
    }
    if observed != expected:
        raise WebControlledValidationRouteClaimError(
            "route claim ledger triggers do not match the sealed contract"
        )


def _normalize_trigger_sql(statement: str) -> str:
    return _normalize_schema_sql(statement)


def _normalize_schema_sql(statement: str) -> str:
    normalized = " ".join(statement.strip().rstrip(";").split())
    normalized = normalized.replace(
        "CREATE TRIGGER IF NOT EXISTS ",
        "CREATE TRIGGER ",
        1,
    )
    return normalized.replace(
        "CREATE TABLE IF NOT EXISTS ",
        "CREATE TABLE ",
        1,
    )


def _require_claim_schema(connection: sqlite3.Connection) -> None:
    columns = connection.execute(
        'SELECT cid, name, type, "notnull", dflt_value, pk, hidden '
        "FROM pragma_table_xinfo(?) ORDER BY cid",
        (_TABLE_NAME,),
    ).fetchall()
    observed_columns = tuple(tuple(row) for row in columns)
    expected_columns = (
        (0, "slot_digest", "TEXT", 0, None, 1, 0),
        (1, "route_digest", "TEXT", 1, None, 0, 0),
        (2, "verification_digest", "TEXT", 1, None, 0, 0),
        (3, "claimed_at", "TEXT", 1, None, 0, 0),
        (4, "receipt_digest", "TEXT", 1, None, 0, 0),
        (5, "receipt_json", "TEXT", 1, None, 0, 0),
    )
    if observed_columns != expected_columns:
        raise WebControlledValidationRouteClaimError(
            "route claim ledger table schema does not match the sealed contract"
        )

    indexes = connection.execute(
        'SELECT name, "unique", origin, partial FROM pragma_index_list(?)',
        (_TABLE_NAME,),
    ).fetchall()
    observed_indexes: set[tuple[str, str]] = set()
    for index in indexes:
        index_name = index[0]
        if (
            type(index_name) is not str
            or index[1] != 1
            or index[2] not in {"pk", "u"}
            or index[3] != 0
        ):
            raise WebControlledValidationRouteClaimError(
                "route claim ledger indexes do not match the sealed contract"
            )
        indexed_columns = connection.execute(
            "SELECT seqno, cid, name FROM pragma_index_info(?) ORDER BY seqno",
            (index_name,),
        ).fetchall()
        if len(indexed_columns) != 1 or indexed_columns[0][0] != 0:
            raise WebControlledValidationRouteClaimError(
                "route claim ledger unique indexes must each bind exactly one column"
            )
        column_name = indexed_columns[0][2]
        if type(column_name) is not str:
            raise WebControlledValidationRouteClaimError(
                "route claim ledger unique index column is invalid"
            )
        observed_indexes.add((str(index[2]), column_name))

    expected_indexes = {
        ("pk", "slot_digest"),
        ("u", "route_digest"),
        ("u", "verification_digest"),
        ("u", "receipt_digest"),
    }
    if observed_indexes != expected_indexes or len(indexes) != len(expected_indexes):
        raise WebControlledValidationRouteClaimError(
            "route claim ledger uniqueness constraints do not match the sealed contract"
        )


def _require_denial_schema(connection: sqlite3.Connection) -> None:
    columns = connection.execute(
        'SELECT cid, name, type, "notnull", dflt_value, pk, hidden '
        "FROM pragma_table_xinfo(?) ORDER BY cid",
        (_DENIAL_TABLE_NAME,),
    ).fetchall()
    observed_columns = tuple(tuple(row) for row in columns)
    expected_columns = (
        (0, "slot_digest", "TEXT", 0, None, 1, 0),
        (1, "route_digest", "TEXT", 1, None, 0, 0),
        (2, "denied_at", "TEXT", 1, None, 0, 0),
        (3, "receipt_digest", "TEXT", 1, None, 0, 0),
        (4, "receipt_json", "TEXT", 1, None, 0, 0),
    )
    if observed_columns != expected_columns:
        raise WebControlledValidationRouteClaimError(
            "route denial ledger table schema does not match the sealed contract"
        )

    indexes = connection.execute(
        'SELECT name, "unique", origin, partial FROM pragma_index_list(?)',
        (_DENIAL_TABLE_NAME,),
    ).fetchall()
    observed_indexes: set[tuple[str, str]] = set()
    for index in indexes:
        index_name = index[0]
        if (
            type(index_name) is not str
            or index[1] != 1
            or index[2] not in {"pk", "u"}
            or index[3] != 0
        ):
            raise WebControlledValidationRouteClaimError(
                "route denial ledger indexes do not match the sealed contract"
            )
        indexed_columns = connection.execute(
            "SELECT seqno, cid, name FROM pragma_index_info(?) ORDER BY seqno",
            (index_name,),
        ).fetchall()
        if len(indexed_columns) != 1 or indexed_columns[0][0] != 0:
            raise WebControlledValidationRouteClaimError(
                "route denial ledger unique indexes must each bind exactly one column"
            )
        column_name = indexed_columns[0][2]
        if type(column_name) is not str:
            raise WebControlledValidationRouteClaimError(
                "route denial ledger unique index column is invalid"
            )
        observed_indexes.add((str(index[2]), column_name))

    expected_indexes = {
        ("pk", "slot_digest"),
        ("u", "route_digest"),
        ("u", "receipt_digest"),
    }
    if observed_indexes != expected_indexes or len(indexes) != len(expected_indexes):
        raise WebControlledValidationRouteClaimError(
            "route denial ledger uniqueness constraints do not match the sealed contract"
        )
