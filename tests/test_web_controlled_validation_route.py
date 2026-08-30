from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest
from pydantic import ValidationError

from pajin.benchmark.models import benchmark_digest
from pajin.workflow import web_controlled_validation_route as route_module
from pajin.workflow.web_controlled_validation_route import (
    WebControlledValidationRouteClaimError,
    WebControlledValidationRouteClaimLedger,
    WebControlledValidationRouteClaimReceipt,
    WebControlledValidationRouteDenialReceipt,
    load_web_controlled_validation_route_claim_receipt,
    load_web_controlled_validation_route_denial_receipt,
)

_SLOT_DIGEST = "1" * 64
_OTHER_SLOT_DIGEST = "2" * 64
_ROUTE_DIGEST = "3" * 64
_OTHER_ROUTE_DIGEST = "4" * 64
_VERIFICATION_DIGEST = "5" * 64
_OTHER_VERIFICATION_DIGEST = "6" * 64
_CLAIMED_AT = datetime(2026, 8, 29, 4, 30, tzinfo=UTC)
_DENIED_AT = datetime(2026, 8, 29, 4, 45, tzinfo=UTC)


def _ledger(tmp_path: Path) -> WebControlledValidationRouteClaimLedger:
    return WebControlledValidationRouteClaimLedger(tmp_path / "route-claims.sqlite3")


def _claim(
    ledger: WebControlledValidationRouteClaimLedger,
    *,
    slot_digest: str = _SLOT_DIGEST,
    route_digest: str = _ROUTE_DIGEST,
    verification_digest: str = _VERIFICATION_DIGEST,
    claimed_at: datetime = _CLAIMED_AT,
) -> WebControlledValidationRouteClaimReceipt:
    return ledger.claim_once(
        slot_digest=slot_digest,
        route_digest=route_digest,
        verification_digest=verification_digest,
        claimed_at=claimed_at,
    )


def _deny(
    ledger: WebControlledValidationRouteClaimLedger,
    *,
    slot_digest: str = _SLOT_DIGEST,
    route_digest: str = _ROUTE_DIGEST,
    denied_at: datetime = _DENIED_AT,
) -> WebControlledValidationRouteDenialReceipt:
    return ledger.seal_denial_if_unclaimed(
        slot_digest=slot_digest,
        route_digest=route_digest,
        denied_at=denied_at,
    )


def _tamper(
    ledger: WebControlledValidationRouteClaimLedger,
    statement: str,
    parameters: tuple[str, ...],
) -> None:
    connection = sqlite3.connect(ledger.path)
    try:
        for trigger_name in route_module._CLAIM_TRIGGER_NAMES:
            connection.execute(f"DROP TRIGGER {trigger_name}")
        connection.execute(statement, parameters)
        for trigger_statement in route_module._TRIGGER_STATEMENTS:
            connection.execute(trigger_statement)
        connection.commit()
    finally:
        connection.close()


def _tamper_denial(
    ledger: WebControlledValidationRouteClaimLedger,
    statement: str,
    parameters: tuple[str, ...],
) -> None:
    connection = sqlite3.connect(ledger.path)
    try:
        for trigger_name in route_module._DENIAL_TRIGGER_NAMES:
            connection.execute(f"DROP TRIGGER {trigger_name}")
        connection.execute(statement, parameters)
        for trigger_statement in route_module._TRIGGER_STATEMENTS:
            connection.execute(trigger_statement)
        connection.commit()
    finally:
        connection.close()


def _schema_objects(path: Path) -> tuple[tuple[object, ...], ...]:
    connection = sqlite3.connect(path)
    try:
        return tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE type IN ('table', 'index', 'view', 'trigger') "
                "ORDER BY type, name"
            )
        )
    finally:
        connection.close()


def test_claim_receipt_is_content_addressed_normalized_and_round_trips(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    claimed_at = datetime(
        2026,
        8,
        29,
        13,
        30,
        tzinfo=timezone(timedelta(hours=9)),
    )

    receipt = _claim(ledger, claimed_at=claimed_at)

    assert receipt.claimed_at == _CLAIMED_AT
    material = receipt.model_dump(
        mode="json",
        by_alias=True,
        exclude={"receipt_digest"},
    )
    assert receipt.receipt_digest == benchmark_digest(
        "pajin.workflow.web-controlled-validation-route-claim-receipt/v1",
        material,
        max_bytes=64 * 1024,
    )
    assert receipt.model_dump(by_alias=True)["apiVersion"] == (
        "pajin.dev/web-controlled-validation-route-claim-receipt/v1alpha1"
    )
    assert receipt.model_dump(by_alias=True)["kind"] == ("WebControlledValidationRouteClaimReceipt")

    loaded = load_web_controlled_validation_route_claim_receipt(
        ledger=ledger,
        receipt=receipt,
    )

    assert loaded == receipt
    assert loaded is not receipt


def test_denial_receipt_is_content_addressed_idempotent_and_round_trips(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    denied_at = datetime(
        2026,
        8,
        29,
        13,
        45,
        tzinfo=timezone(timedelta(hours=9)),
    )

    receipt = _deny(ledger, denied_at=denied_at)
    reopened = _ledger(tmp_path)
    retried = _deny(reopened, denied_at=denied_at)
    loaded = load_web_controlled_validation_route_denial_receipt(
        ledger=reopened,
        receipt=receipt,
    )

    assert receipt.denied_at == _DENIED_AT
    material = receipt.model_dump(
        mode="json",
        by_alias=True,
        exclude={"receipt_digest"},
    )
    assert receipt.receipt_digest == benchmark_digest(
        "pajin.workflow.web-controlled-validation-route-denial-receipt/v1",
        material,
        max_bytes=64 * 1024,
    )
    assert receipt.model_dump(by_alias=True)["apiVersion"] == (
        "pajin.dev/web-controlled-validation-route-denial-receipt/v1alpha1"
    )
    assert receipt.model_dump(by_alias=True)["kind"] == (
        "WebControlledValidationRouteDenialReceipt"
    )
    assert retried == receipt
    assert retried is not receipt
    assert loaded == receipt
    assert loaded is not receipt

    connection = sqlite3.connect(ledger.path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM web_controlled_validation_route_denials"
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_exact_retry_is_rejected_as_consumed(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)

    _claim(ledger)

    with pytest.raises(WebControlledValidationRouteClaimError, match="consumed"):
        _claim(ledger)
    connection = sqlite3.connect(ledger.path)
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM web_controlled_validation_route_claims"
        ).fetchone()
    finally:
        connection.close()
    assert count == (1,)


@pytest.mark.parametrize(
    ("changed"),
    [
        {"route_digest": _OTHER_ROUTE_DIGEST},
        {"verification_digest": _OTHER_VERIFICATION_DIGEST},
        {"claimed_at": _CLAIMED_AT + timedelta(seconds=1)},
    ],
    ids=["route", "verification", "claimed-at"],
)
def test_same_slot_rejects_any_changed_claim_input(
    tmp_path: Path,
    changed: dict[str, str | datetime],
) -> None:
    ledger = _ledger(tmp_path)
    _claim(ledger)

    with pytest.raises(WebControlledValidationRouteClaimError, match="consumed"):
        _claim(ledger, **changed)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("changed"),
    [
        {"route_digest": _OTHER_ROUTE_DIGEST},
        {"denied_at": _DENIED_AT + timedelta(seconds=1)},
    ],
    ids=["route", "denied-at"],
)
def test_same_slot_rejects_any_changed_denial_input(
    tmp_path: Path,
    changed: dict[str, str | datetime],
) -> None:
    ledger = _ledger(tmp_path)
    _deny(ledger)

    with pytest.raises(WebControlledValidationRouteClaimError, match="different denial"):
        _deny(ledger, **changed)  # type: ignore[arg-type]


def test_another_slot_cannot_reuse_denied_route(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    _deny(ledger)

    with pytest.raises(WebControlledValidationRouteClaimError, match="another denial slot"):
        _deny(ledger, slot_digest=_OTHER_SLOT_DIGEST)


@pytest.mark.parametrize(
    ("slot_digest", "route_digest"),
    [
        (_SLOT_DIGEST, _OTHER_ROUTE_DIGEST),
        (_OTHER_SLOT_DIGEST, _ROUTE_DIGEST),
    ],
    ids=["denied-slot", "denied-route"],
)
def test_denial_blocks_claim_by_slot_or_route(
    tmp_path: Path,
    slot_digest: str,
    route_digest: str,
) -> None:
    ledger = _ledger(tmp_path)
    _deny(ledger)

    with pytest.raises(WebControlledValidationRouteClaimError, match="durably denied"):
        _claim(
            ledger,
            slot_digest=slot_digest,
            route_digest=route_digest,
        )


@pytest.mark.parametrize(
    ("slot_digest", "route_digest"),
    [
        (_SLOT_DIGEST, _OTHER_ROUTE_DIGEST),
        (_OTHER_SLOT_DIGEST, _ROUTE_DIGEST),
    ],
    ids=["claimed-slot", "claimed-route"],
)
def test_claim_blocks_denial_by_slot_or_route(
    tmp_path: Path,
    slot_digest: str,
    route_digest: str,
) -> None:
    ledger = _ledger(tmp_path)
    _claim(ledger)

    with pytest.raises(WebControlledValidationRouteClaimError, match="already been claimed"):
        _deny(
            ledger,
            slot_digest=slot_digest,
            route_digest=route_digest,
        )


@pytest.mark.parametrize(
    ("route_digest", "verification_digest"),
    [
        (_ROUTE_DIGEST, _OTHER_VERIFICATION_DIGEST),
        (_OTHER_ROUTE_DIGEST, _VERIFICATION_DIGEST),
        (_ROUTE_DIGEST, _VERIFICATION_DIGEST),
    ],
    ids=["route-reused", "verification-reused", "both-reused"],
)
def test_another_slot_cannot_reuse_route_or_verification(
    tmp_path: Path,
    route_digest: str,
    verification_digest: str,
) -> None:
    ledger = _ledger(tmp_path)
    _claim(ledger)

    with pytest.raises(WebControlledValidationRouteClaimError, match="another slot"):
        _claim(
            ledger,
            slot_digest=_OTHER_SLOT_DIGEST,
            route_digest=route_digest,
            verification_digest=verification_digest,
        )


def test_receipt_rejects_extra_keys_and_loader_rejects_smuggled_models(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    receipt = _claim(ledger)
    material = receipt.model_dump(mode="python", by_alias=True)

    with pytest.raises(ValidationError):
        WebControlledValidationRouteClaimReceipt.model_validate(
            {**material, "hiddenAuthority": True}
        )
    with pytest.raises(ValidationError):
        WebControlledValidationRouteClaimReceipt.model_validate(
            {**material, "receiptDigest": "short"}
        )

    hidden = receipt.model_copy(update={"hidden_authority": True})
    with pytest.raises(WebControlledValidationRouteClaimError, match="hidden"):
        load_web_controlled_validation_route_claim_receipt(
            ledger=ledger,
            receipt=hidden,
        )

    changed = receipt.model_copy(update={"route_digest": _OTHER_ROUTE_DIGEST})
    with pytest.raises(WebControlledValidationRouteClaimError, match="canonically valid"):
        load_web_controlled_validation_route_claim_receipt(
            ledger=ledger,
            receipt=changed,
        )

    class ReceiptSubclass(WebControlledValidationRouteClaimReceipt):
        pass

    subclass = ReceiptSubclass.model_validate(material)
    with pytest.raises(WebControlledValidationRouteClaimError, match="exact"):
        load_web_controlled_validation_route_claim_receipt(
            ledger=ledger,
            receipt=subclass,
        )


def test_denial_receipt_rejects_extra_keys_and_loader_rejects_smuggled_models(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    receipt = _deny(ledger)
    material = receipt.model_dump(mode="python", by_alias=True)

    with pytest.raises(ValidationError):
        WebControlledValidationRouteDenialReceipt.model_validate(
            {**material, "hiddenAuthority": True}
        )
    hidden = receipt.model_copy(update={"hidden_authority": True})
    with pytest.raises(WebControlledValidationRouteClaimError, match="hidden"):
        load_web_controlled_validation_route_denial_receipt(
            ledger=ledger,
            receipt=hidden,
        )

    changed = receipt.model_copy(update={"route_digest": _OTHER_ROUTE_DIGEST})
    with pytest.raises(WebControlledValidationRouteClaimError, match="canonically valid"):
        load_web_controlled_validation_route_denial_receipt(
            ledger=ledger,
            receipt=changed,
        )

    class DenialReceiptSubclass(WebControlledValidationRouteDenialReceipt):
        pass

    subclass = DenialReceiptSubclass.model_validate(material)
    with pytest.raises(WebControlledValidationRouteClaimError, match="exact"):
        load_web_controlled_validation_route_denial_receipt(
            ledger=ledger,
            receipt=subclass,
        )


@pytest.mark.parametrize(
    ("statement", "parameters"),
    [
        (
            """UPDATE web_controlled_validation_route_claims
            SET receipt_json = receipt_json || ' '
            WHERE slot_digest = ?""",
            (_SLOT_DIGEST,),
        ),
        (
            """UPDATE web_controlled_validation_route_claims
            SET route_digest = ?
            WHERE slot_digest = ?""",
            (_OTHER_ROUTE_DIGEST, _SLOT_DIGEST),
        ),
        (
            """UPDATE web_controlled_validation_route_claims
            SET receipt_digest = ?
            WHERE slot_digest = ?""",
            ("7" * 64, _SLOT_DIGEST),
        ),
    ],
    ids=["json", "column", "digest"],
)
def test_loader_rejects_tampered_database_state(
    tmp_path: Path,
    statement: str,
    parameters: tuple[str, ...],
) -> None:
    ledger = _ledger(tmp_path)
    receipt = _claim(ledger)
    _tamper(ledger, statement, parameters)

    with pytest.raises(WebControlledValidationRouteClaimError):
        load_web_controlled_validation_route_claim_receipt(
            ledger=ledger,
            receipt=receipt,
        )


@pytest.mark.parametrize(
    ("statement", "parameters"),
    [
        (
            """UPDATE web_controlled_validation_route_denials
            SET receipt_json = receipt_json || ' '
            WHERE slot_digest = ?""",
            (_SLOT_DIGEST,),
        ),
        (
            """UPDATE web_controlled_validation_route_denials
            SET route_digest = ?
            WHERE slot_digest = ?""",
            (_OTHER_ROUTE_DIGEST, _SLOT_DIGEST),
        ),
        (
            """UPDATE web_controlled_validation_route_denials
            SET receipt_digest = ?
            WHERE slot_digest = ?""",
            ("7" * 64, _SLOT_DIGEST),
        ),
    ],
    ids=["json", "column", "digest"],
)
def test_denial_loader_rejects_tampered_database_state(
    tmp_path: Path,
    statement: str,
    parameters: tuple[str, ...],
) -> None:
    ledger = _ledger(tmp_path)
    receipt = _deny(ledger)
    _tamper_denial(ledger, statement, parameters)

    with pytest.raises(WebControlledValidationRouteClaimError):
        load_web_controlled_validation_route_denial_receipt(
            ledger=ledger,
            receipt=receipt,
        )


def test_database_triggers_reject_update_delete_and_replace(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    _claim(ledger)
    connection = sqlite3.connect(ledger.path)
    try:
        row = connection.execute("SELECT * FROM web_controlled_validation_route_claims").fetchone()
        assert row is not None

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """UPDATE web_controlled_validation_route_claims
                SET claimed_at = ? WHERE slot_digest = ?""",
                ((_CLAIMED_AT + timedelta(seconds=1)).isoformat(), _SLOT_DIGEST),
            )
        connection.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM web_controlled_validation_route_claims WHERE slot_digest = ?",
                (_SLOT_DIGEST,),
            )
        connection.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="cannot be replaced"):
            connection.execute(
                """INSERT OR REPLACE INTO web_controlled_validation_route_claims (
                    slot_digest, route_digest, verification_digest, claimed_at,
                    receipt_digest, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                row,
            )
        connection.rollback()
    finally:
        connection.close()


def test_denial_database_triggers_reject_update_delete_and_replace(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    _deny(ledger)
    connection = sqlite3.connect(ledger.path)
    try:
        row = connection.execute("SELECT * FROM web_controlled_validation_route_denials").fetchone()
        assert row is not None

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """UPDATE web_controlled_validation_route_denials
                SET denied_at = ? WHERE slot_digest = ?""",
                ((_DENIED_AT + timedelta(seconds=1)).isoformat(), _SLOT_DIGEST),
            )
        connection.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM web_controlled_validation_route_denials WHERE slot_digest = ?",
                (_SLOT_DIGEST,),
            )
        connection.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="cannot be replaced"):
            connection.execute(
                """INSERT OR REPLACE INTO web_controlled_validation_route_denials (
                    slot_digest, route_digest, denied_at, receipt_digest, receipt_json
                ) VALUES (?, ?, ?, ?, ?)""",
                row,
            )
        connection.rollback()
    finally:
        connection.close()


def test_cross_table_triggers_reject_claim_and_denial_conflicts(tmp_path: Path) -> None:
    denied_ledger = _ledger(tmp_path / "denied")
    _deny(denied_ledger)
    claim_candidate = WebControlledValidationRouteClaimReceipt(
        slotDigest=_SLOT_DIGEST,
        routeDigest=_ROUTE_DIGEST,
        verificationDigest=_VERIFICATION_DIGEST,
        claimedAt=_CLAIMED_AT,
    )
    denied_connection = sqlite3.connect(denied_ledger.path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="durably denied"):
            denied_connection.execute(
                """INSERT INTO web_controlled_validation_route_claims (
                    slot_digest, route_digest, verification_digest, claimed_at,
                    receipt_digest, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    claim_candidate.slot_digest,
                    claim_candidate.route_digest,
                    claim_candidate.verification_digest,
                    claim_candidate.claimed_at.isoformat(),
                    claim_candidate.receipt_digest,
                    claim_candidate.model_dump_json(by_alias=True),
                ),
            )
        denied_connection.rollback()
    finally:
        denied_connection.close()

    claimed_ledger = _ledger(tmp_path / "claimed")
    _claim(claimed_ledger)
    denial_candidate = WebControlledValidationRouteDenialReceipt(
        slotDigest=_SLOT_DIGEST,
        routeDigest=_ROUTE_DIGEST,
        deniedAt=_DENIED_AT,
    )
    claimed_connection = sqlite3.connect(claimed_ledger.path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="already claimed"):
            claimed_connection.execute(
                """INSERT INTO web_controlled_validation_route_denials (
                    slot_digest, route_digest, denied_at, receipt_digest, receipt_json
                ) VALUES (?, ?, ?, ?, ?)""",
                (
                    denial_candidate.slot_digest,
                    denial_candidate.route_digest,
                    denial_candidate.denied_at.isoformat(),
                    denial_candidate.receipt_digest,
                    denial_candidate.model_dump_json(by_alias=True),
                ),
            )
        claimed_connection.rollback()
    finally:
        claimed_connection.close()


def test_concurrent_exact_claims_have_one_permanent_winner(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    barrier = Barrier(2)

    def run_claim() -> tuple[str, object]:
        barrier.wait()
        try:
            return "claimed", _claim(ledger)
        except WebControlledValidationRouteClaimError as error:
            return "rejected", error

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: run_claim(), range(2)))

    assert sorted(status for status, _ in outcomes) == ["claimed", "rejected"]


def test_concurrent_conflicting_claims_have_one_permanent_winner(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    barrier = Barrier(2)

    def run_claim(route_digest: str) -> tuple[str, object]:
        barrier.wait()
        try:
            return "claimed", _claim(ledger, route_digest=route_digest)
        except WebControlledValidationRouteClaimError as error:
            return "rejected", error

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(run_claim, _ROUTE_DIGEST),
            executor.submit(run_claim, _OTHER_ROUTE_DIGEST),
        ]
        outcomes = [future.result() for future in futures]

    assert sorted(status for status, _ in outcomes) == ["claimed", "rejected"]
    winner = next(value for status, value in outcomes if status == "claimed")
    assert isinstance(winner, WebControlledValidationRouteClaimReceipt)
    with pytest.raises(WebControlledValidationRouteClaimError, match="consumed"):
        _claim(ledger, route_digest=winner.route_digest)
    losing_route = _OTHER_ROUTE_DIGEST if winner.route_digest == _ROUTE_DIGEST else _ROUTE_DIGEST
    with pytest.raises(WebControlledValidationRouteClaimError, match="consumed"):
        _claim(ledger, route_digest=losing_route)


def test_concurrent_claim_and_denial_have_one_permanent_winner(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    barrier = Barrier(2)

    def run_claim() -> tuple[str, object]:
        barrier.wait()
        try:
            return "claimed", _claim(ledger)
        except WebControlledValidationRouteClaimError as error:
            return "rejected", error

    def run_denial() -> tuple[str, object]:
        barrier.wait()
        try:
            return "denied", _deny(ledger)
        except WebControlledValidationRouteClaimError as error:
            return "rejected", error

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run_claim), executor.submit(run_denial)]
        outcomes = [future.result() for future in futures]

    statuses = sorted(status for status, _ in outcomes)
    assert statuses in (["claimed", "rejected"], ["denied", "rejected"])
    winner_status, winner = next(
        (status, value) for status, value in outcomes if status != "rejected"
    )
    if winner_status == "claimed":
        assert isinstance(winner, WebControlledValidationRouteClaimReceipt)
        assert (
            load_web_controlled_validation_route_claim_receipt(
                ledger=ledger,
                receipt=winner,
            )
            == winner
        )
        with pytest.raises(WebControlledValidationRouteClaimError, match="claimed"):
            _deny(ledger)
    else:
        assert isinstance(winner, WebControlledValidationRouteDenialReceipt)
        assert (
            load_web_controlled_validation_route_denial_receipt(
                ledger=ledger,
                receipt=winner,
            )
            == winner
        )
        with pytest.raises(WebControlledValidationRouteClaimError, match="denied"):
            _claim(ledger)

    connection = sqlite3.connect(ledger.path)
    try:
        claim_count = connection.execute(
            "SELECT COUNT(*) FROM web_controlled_validation_route_claims"
        ).fetchone()
        denial_count = connection.execute(
            "SELECT COUNT(*) FROM web_controlled_validation_route_denials"
        ).fetchone()
    finally:
        connection.close()
    assert claim_count is not None
    assert denial_count is not None
    assert claim_count[0] + denial_count[0] == 1


def test_require_unclaimed_is_read_only_and_rejects_slot_or_route_claims(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    ledger.require_unclaimed(
        slot_digest=_SLOT_DIGEST,
        route_digest=_ROUTE_DIGEST,
    )
    _claim(ledger)

    with pytest.raises(WebControlledValidationRouteClaimError, match="already been claimed"):
        ledger.require_unclaimed(
            slot_digest=_SLOT_DIGEST,
            route_digest=_OTHER_ROUTE_DIGEST,
        )
    with pytest.raises(WebControlledValidationRouteClaimError, match="already been claimed"):
        ledger.require_unclaimed(
            slot_digest=_OTHER_SLOT_DIGEST,
            route_digest=_ROUTE_DIGEST,
        )
    connection = sqlite3.connect(ledger.path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM web_controlled_validation_route_claims"
        ).fetchone() == (1,)
    finally:
        connection.close()


@pytest.mark.parametrize("field", ("slot_digest", "route_digest"))
def test_require_unclaimed_rejects_malformed_digest(tmp_path: Path, field: str) -> None:
    ledger = _ledger(tmp_path)
    values = {
        "slot_digest": _SLOT_DIGEST,
        "route_digest": _ROUTE_DIGEST,
    }
    values[field] = "short"

    with pytest.raises(WebControlledValidationRouteClaimError, match="digest is invalid"):
        ledger.require_unclaimed(**values)


@pytest.mark.parametrize(
    ("slot_digest", "route_digest", "verification_digest"),
    [
        ("short", _ROUTE_DIGEST, _VERIFICATION_DIGEST),
        (_SLOT_DIGEST, "A" * 64, _VERIFICATION_DIGEST),
        (_SLOT_DIGEST, _ROUTE_DIGEST, "g" * 64),
    ],
)
def test_claim_rejects_malformed_digests(
    tmp_path: Path,
    slot_digest: str,
    route_digest: str,
    verification_digest: str,
) -> None:
    ledger = _ledger(tmp_path)

    with pytest.raises(WebControlledValidationRouteClaimError, match="inputs are invalid"):
        _claim(
            ledger,
            slot_digest=slot_digest,
            route_digest=route_digest,
            verification_digest=verification_digest,
        )


def test_claim_rejects_naive_datetime(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)

    with pytest.raises(WebControlledValidationRouteClaimError, match="inputs are invalid"):
        _claim(ledger, claimed_at=datetime(2026, 8, 29, 4, 30))


@pytest.mark.parametrize(
    ("slot_digest", "route_digest", "denied_at"),
    [
        ("short", _ROUTE_DIGEST, _DENIED_AT),
        (_SLOT_DIGEST, "A" * 64, _DENIED_AT),
        (_SLOT_DIGEST, _ROUTE_DIGEST, datetime(2026, 8, 29, 4, 45)),
    ],
    ids=["slot", "route", "naive-time"],
)
def test_denial_rejects_malformed_inputs(
    tmp_path: Path,
    slot_digest: str,
    route_digest: str,
    denied_at: datetime,
) -> None:
    ledger = _ledger(tmp_path)

    with pytest.raises(WebControlledValidationRouteClaimError, match="inputs are invalid"):
        _deny(
            ledger,
            slot_digest=slot_digest,
            route_digest=route_digest,
            denied_at=denied_at,
        )


def test_ledger_rejects_hardlinked_database(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    hardlink = tmp_path / "route-claims-hardlink.sqlite3"
    try:
        os.link(ledger.path, hardlink)
    except OSError as error:
        pytest.skip(f"hard links are unavailable: {error}")

    with pytest.raises(WebControlledValidationRouteClaimError, match="exactly one"):
        WebControlledValidationRouteClaimLedger(hardlink)


def test_ledger_rejects_symlinked_database(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    symlink = tmp_path / "route-claims-symlink.sqlite3"
    try:
        symlink.symlink_to(ledger.path)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symbolic links are unavailable: {error}")

    with pytest.raises(WebControlledValidationRouteClaimError, match="non-link"):
        WebControlledValidationRouteClaimLedger(symlink)


def test_ledger_rejects_linked_ancestor_before_creating_directories(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"directory symbolic links are unavailable: {error}")

    requested_parent = linked_parent / "must-not-be-created"
    with pytest.raises(WebControlledValidationRouteClaimError, match="parent paths"):
        WebControlledValidationRouteClaimLedger(requested_parent / "claims.sqlite3")

    assert not (real_parent / "must-not-be-created").exists()


@pytest.mark.parametrize(
    "tamper_statement",
    [
        "DROP TABLE web_controlled_validation_route_denials",
        "DROP TRIGGER web_controlled_validation_route_claims_no_update",
        "CREATE TABLE unexpected_route_state (value TEXT)",
        (
            "CREATE UNIQUE INDEX unexpected_route_index "
            "ON web_controlled_validation_route_claims(claimed_at)"
        ),
        (
            "CREATE VIEW unexpected_route_view AS "
            "SELECT slot_digest FROM web_controlled_validation_route_claims"
        ),
        """CREATE TRIGGER unexpected_route_trigger
        BEFORE INSERT ON web_controlled_validation_route_claims
        BEGIN
            SELECT 1;
        END""",
    ],
    ids=[
        "missing-table",
        "missing-trigger",
        "extra-table",
        "extra-index",
        "extra-view",
        "extra-trigger",
    ],
)
def test_fresh_constructor_rejects_schema_object_tamper_without_repair(
    tmp_path: Path,
    tamper_statement: str,
) -> None:
    ledger = _ledger(tmp_path)
    connection = sqlite3.connect(ledger.path)
    try:
        connection.execute(tamper_statement)
        connection.commit()
    finally:
        connection.close()
    tampered_objects = _schema_objects(ledger.path)

    with pytest.raises(WebControlledValidationRouteClaimError):
        WebControlledValidationRouteClaimLedger(ledger.path)

    assert _schema_objects(ledger.path) == tampered_objects


def test_fresh_constructor_rejects_changed_table_definition_without_repair(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    connection = sqlite3.connect(ledger.path)
    try:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (route_module._TABLE_NAME,),
        ).fetchone()
        assert row is not None
        table_sql = row[0]
        assert type(table_sql) is str
        changed_sql = table_sql.rstrip()[:-1] + ", CHECK (length(slot_digest) = 64))"
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_master SET sql = ? WHERE type = 'table' AND name = ?",
            (changed_sql, route_module._TABLE_NAME),
        )
        connection.execute("PRAGMA writable_schema = OFF")
        schema_version = connection.execute("PRAGMA schema_version").fetchone()
        assert schema_version is not None
        connection.execute(f"PRAGMA schema_version = {int(schema_version[0]) + 1}")
        connection.commit()
    finally:
        connection.close()
    tampered_objects = _schema_objects(ledger.path)

    with pytest.raises(WebControlledValidationRouteClaimError, match="schema objects"):
        WebControlledValidationRouteClaimLedger(ledger.path)

    assert _schema_objects(ledger.path) == tampered_objects


def test_fresh_constructor_rejects_wal_drift_without_repair(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    connection = sqlite3.connect(ledger.path)
    try:
        assert connection.execute("PRAGMA journal_mode = WAL").fetchone() == ("wal",)
    finally:
        connection.close()

    with pytest.raises(WebControlledValidationRouteClaimError, match="DELETE journal"):
        WebControlledValidationRouteClaimLedger(ledger.path)

    connection = sqlite3.connect(ledger.path)
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    finally:
        connection.close()


@pytest.mark.parametrize("operation", ["read", "write"])
def test_each_transaction_rechecks_exact_schema_objects(
    tmp_path: Path,
    operation: str,
) -> None:
    ledger = _ledger(tmp_path)
    connection = sqlite3.connect(ledger.path)
    try:
        connection.execute(
            "CREATE VIEW unexpected_route_view AS "
            "SELECT slot_digest FROM web_controlled_validation_route_claims"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(WebControlledValidationRouteClaimError, match="schema objects"):
        if operation == "read":
            ledger.require_unclaimed(
                slot_digest=_SLOT_DIGEST,
                route_digest=_ROUTE_DIGEST,
            )
        else:
            _claim(ledger)


def test_deleted_database_is_not_recreated_by_existing_ledger(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    ledger.path.unlink()

    with pytest.raises(WebControlledValidationRouteClaimError, match="could not open"):
        _claim(ledger)

    assert not ledger.path.exists()


@pytest.mark.parametrize(
    "table_statement",
    [
        """CREATE TABLE web_controlled_validation_route_claims (
            slot_digest TEXT PRIMARY KEY,
            route_digest TEXT UNIQUE,
            verification_digest TEXT NOT NULL UNIQUE,
            claimed_at TEXT NOT NULL,
            receipt_digest TEXT NOT NULL UNIQUE,
            receipt_json TEXT NOT NULL
        )""",
        """CREATE TABLE web_controlled_validation_route_claims (
            slot_digest TEXT PRIMARY KEY,
            route_digest TEXT NOT NULL,
            verification_digest TEXT NOT NULL UNIQUE,
            claimed_at TEXT NOT NULL,
            receipt_digest TEXT NOT NULL UNIQUE,
            receipt_json TEXT NOT NULL
        )""",
    ],
    ids=["missing-not-null", "missing-unique"],
)
def test_ledger_rejects_weakened_claim_schema(
    tmp_path: Path,
    table_statement: str,
) -> None:
    path = tmp_path / "weakened.sqlite3"
    connection = sqlite3.connect(path)
    try:
        connection.execute(table_statement)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(WebControlledValidationRouteClaimError, match=r"schema|uniqueness"):
        WebControlledValidationRouteClaimLedger(path)


@pytest.mark.parametrize(
    "table_statement",
    [
        """CREATE TABLE web_controlled_validation_route_denials (
            slot_digest TEXT PRIMARY KEY,
            route_digest TEXT UNIQUE,
            denied_at TEXT NOT NULL,
            receipt_digest TEXT NOT NULL UNIQUE,
            receipt_json TEXT NOT NULL
        )""",
        """CREATE TABLE web_controlled_validation_route_denials (
            slot_digest TEXT PRIMARY KEY,
            route_digest TEXT NOT NULL,
            denied_at TEXT NOT NULL,
            receipt_digest TEXT NOT NULL UNIQUE,
            receipt_json TEXT NOT NULL
        )""",
    ],
    ids=["missing-not-null", "missing-unique"],
)
def test_ledger_rejects_weakened_denial_schema(
    tmp_path: Path,
    table_statement: str,
) -> None:
    path = tmp_path / "weakened-denial.sqlite3"
    connection = sqlite3.connect(path)
    try:
        connection.execute(table_statement)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(WebControlledValidationRouteClaimError, match=r"schema|uniqueness"):
        WebControlledValidationRouteClaimLedger(path)


def test_ledger_rejects_same_name_weakened_trigger_definition(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    trigger_name = "web_controlled_validation_route_denials_no_update"
    connection = sqlite3.connect(ledger.path)
    try:
        connection.execute(f"DROP TRIGGER {trigger_name}")
        connection.execute(
            f"""CREATE TRIGGER {trigger_name}
            BEFORE UPDATE ON web_controlled_validation_route_denials
            BEGIN
                SELECT 1;
            END"""
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(WebControlledValidationRouteClaimError, match="triggers"):
        WebControlledValidationRouteClaimLedger(ledger.path)


def test_failed_write_connection_setup_closes_partial_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingConnection:
        row_factory: object = None
        closed = False

        def execute(self, statement: str) -> None:
            if statement == "PRAGMA synchronous = FULL":
                raise sqlite3.OperationalError("injected synchronous failure")

        def close(self) -> None:
            self.closed = True

    connection = FailingConnection()
    monkeypatch.setattr(sqlite3, "connect", lambda *args, **kwargs: connection)
    ledger = object.__new__(WebControlledValidationRouteClaimLedger)
    ledger.path = tmp_path / "unused.sqlite3"

    with pytest.raises(WebControlledValidationRouteClaimError, match="could not open"):
        ledger._open_write_connection()

    assert connection.closed
