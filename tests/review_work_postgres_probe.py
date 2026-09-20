"""Explicit TLS PostgreSQL probes for the runner's newly owned database only."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DatabaseError

import tests.test_review_assignments as assignments
import tests.test_review_work as work_tests
from pajin.control_plane.database import V16_CONTROL_PLANE_TABLES
from tests.operational_postgres_probe import owned_url
from tests.test_control_plane_web import APPROVER_TOKEN, OPERATOR_TOKEN, _auth

pytest_plugins = ("tests.test_review_assignments",)


@pytest.fixture(autouse=True)
def owned_postgres(monkeypatch):
    url = owned_url()
    engine = create_engine(url)
    with engine.begin() as connection:
        assert (
            connection.scalar(text("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"))
            is True
        )
        connection.exec_driver_sql("DROP SCHEMA public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")
    original = assignments._settings
    monkeypatch.setattr(
        assignments, "_settings", lambda path: replace(original(path), database_url=url)
    )
    yield
    engine.dispose()


@pytest.mark.parametrize(
    "case",
    [
        "receipt_at_revision_200_preserves_every_review_byte_and_restarts",
        "receipt_exact_retry_concurrent_writers_and_identity_mismatch",
        "demoted_recipient_cannot_write_receipt",
        "filters_and_independent_ack_change_only_personal_unread_state",
        "empty_filtered_page_continues_and_cursor_is_principal_filter_kind_bound",
    ],
)
def test_real_server_work_contract(assigned_api, case):
    getattr(work_tests, "test_" + case)(assigned_api)


@pytest.mark.parametrize("legacy_first", [False, True])
def test_real_server_legacy_receipt_compatibility(assigned_api, legacy_first):
    work_tests.test_legacy_and_independent_receipts_cannot_double_ack(assigned_api, legacy_first)


def test_simultaneous_legacy_and_new_receipt_have_one_winner(assigned_api):
    client, url, _, _ = assigned_api
    assert assignments.assign(client, url).status_code == 200
    payload = work_tests.receipt_payload(client)
    writes = [
        (
            url + "/notification-ack",
            {"requestKey": "legacy", "expectedRevision": 2, "assignmentRevision": 2},
        ),
        (work_tests.work(url) + "/notification-ack", payload),
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(
            pool.map(
                lambda item: client.post(item[0], json=item[1], headers=_auth(APPROVER_TOKEN)),
                writes,
            )
        )
    assert sorted(r.status_code for r in result) == [200, 409]
    receipts = client.get(
        work_tests.work(url) + "/notification-receipts", headers=_auth(APPROVER_TOKEN)
    ).json()
    retained = work_tests.history(client, url)
    assert len(receipts) + (len(retained) - 2) == 1
    assert client.get(assignments.INBOX, headers=_auth(APPROVER_TOKEN)).json()["items"][0][
        "acknowledged"
    ]


def test_postgres_schema16_migration_and_statement_level_guards(assigned_api):
    client, url, _, _ = assigned_api
    assignments.assign(client, url)
    before = work_tests.history(client, url)
    repository = client.app.state.repository
    with repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE cp_review_notification_receipts")
        connection.exec_driver_sql(
            "DROP FUNCTION pajin_cp_reject_review_notification_receipt_mutation()"
        )
        connection.exec_driver_sql("DELETE FROM cp_schema_version WHERE version=17")
    assert set(inspect(repository.engine).get_table_names()) == V16_CONTROL_PLANE_TABLES
    repository.initialize()
    repository.initialize()
    assert repository.schema_version() == 17
    assert work_tests.history(client, url) == before
    receipt = client.post(
        work_tests.work(url) + "/notification-ack",
        json=work_tests.receipt_payload(client),
        headers=_auth(APPROVER_TOKEN),
    )
    assert receipt.status_code == 200, receipt.text
    for sql in (
        "UPDATE cp_review_notification_receipts SET actor='changed'",
        "DELETE FROM cp_review_notification_receipts",
        "TRUNCATE TABLE cp_review_notification_receipts",
        "INSERT INTO cp_review_notification_receipts SELECT * FROM cp_review_notification_receipts "
        "ON CONFLICT (review_id, assignment_revision, actor) DO UPDATE SET actor_role='operator'",
    ):
        with (
            pytest.raises(DatabaseError, match="append-only"),
            repository.engine.begin() as connection,
        ):
            connection.exec_driver_sql(sql)
    repository.initialize()
    assert client.get(
        work_tests.work(url) + "/notification-receipts", headers=_auth(APPROVER_TOKEN)
    ).json() == [receipt.json()]


def test_postgres_followup_duplicate_writers_preserve_full_parent(assigned_api):
    client, url, _, _ = assigned_api
    full = work_tests.full_review(client, url)
    before = work_tests.history(client, url)
    payload = {
        "requestKey": "followup",
        "expectedRevision": 200,
        "expectedDigest": full["recordDigest"],
        "title": "Follow-up",
        "reason": "Continue review",
    }
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(
            pool.map(
                lambda _: client.post(
                    work_tests.work(url) + "/follow-up", json=payload, headers=_auth(OPERATOR_TOKEN)
                ),
                range(2),
            )
        )
    assert [r.status_code for r in result] == [200, 200]
    assert result[0].json() == result[1].json()
    assert result[0].json()["state"] == "open" and result[0].json()["revision"] == 1
    assert work_tests.history(client, url) == before
    assert len(client.get(assignments.BASE, headers=_auth(OPERATOR_TOKEN)).json()["items"]) == 2
