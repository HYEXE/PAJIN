"""Bounded filtered work queues, independent receipts and preserved full-review continuation."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlalchemy.exc import DatabaseError

from pajin.control_plane.database import (
    CURRENT_SCHEMA_VERSION,
    V16_CONTROL_PLANE_TABLES,
    MeasuredReviewRevisionRecord,
    SchemaInitializationError,
)
from pajin.control_plane.measured_reviews.models import ReviewRevision
from tests.test_control_plane_web import (
    APPROVER_TOKEN,
    AUDITOR_TOKEN,
    OPERATOR_TOKEN,
    WORKER_TOKEN,
    _auth,
)
from tests.test_review_assignments import BASE, INBOX, assign

pytest_plugins = ("tests.test_review_assignments",)
SEARCH = "/v2/measured-reviews"
NOTICES = "/v2/measured-review-inbox"


def work(url):
    return url.replace(BASE, SEARCH, 1)


def history(client, url):
    response = client.get(url + "/history", headers=_auth(OPERATOR_TOKEN))
    assert response.status_code == 200, response.text
    return response.json()


def full_review(client, url):
    """Retain 200 real canonical commands, avoiding 199 redundant HTTP renders in fixtures."""
    prior = ReviewRevision.model_validate_json(json.dumps(history(client, url)[-1]))
    rows = []
    for sequence in range(prior.revision + 1, 201):
        revision = ReviewRevision.model_validate(
            {
                "apiVersion": "pajin.dev/measured-review-revision/v2",
                "reviewId": prior.review_id,
                "revision": sequence,
                "previousDigest": prior.record_digest,
                "actor": "web-operator",
                "actorRole": "operator",
                "recordedAt": datetime.now(UTC) - timedelta(seconds=201 - sequence),
                "requestKey": f"full-{prior.review_id}-{sequence}",
                "requestDigest": "b" * 64,
                "command": {
                    "action": "assigned",
                    "assignee": "web-approver" if sequence % 2 == 0 else "web-operator",
                    "reason": "Retained bounded assignment",
                },
            }
        )
        # The opening time is part of the valid ordering, even in a fast seeded fixture.
        if revision.recorded_at < prior.recorded_at:
            material = revision.model_dump(mode="json", by_alias=True)
            material.pop("recordDigest")
            material["recordedAt"] = prior.recorded_at.isoformat()
            revision = ReviewRevision.model_validate_json(json.dumps(material))
        rows.append(
            MeasuredReviewRevisionRecord(
                review_id=revision.review_id,
                revision=sequence,
                source_domain="ai",
                previous_digest=revision.previous_digest,
                actor=revision.actor,
                actor_role=revision.actor_role,
                recorded_at=revision.recorded_at,
                request_key=revision.request_key,
                request_digest=revision.request_digest,
                record_digest=revision.record_digest,
                payload=revision.model_dump(mode="json", by_alias=True),
            )
        )
        prior = revision
    with client.app.state.repository.transaction() as session:
        session.add_all(rows)
    response = client.get(url, headers=_auth(OPERATOR_TOKEN))
    assert response.status_code == 200, response.text
    return response.json()


def receipt_payload(client, *, key="receipt", revision=2):
    notices = client.get(NOTICES, headers=_auth(APPROVER_TOKEN)).json()["items"]
    notice = next(n for n in notices if n["assignmentRevision"] == revision)
    return {
        "requestKey": key,
        "notificationId": notice["notificationId"],
        "assignmentRevision": revision,
    }


def test_receipt_at_revision_200_preserves_every_review_byte_and_restarts(assigned_api):
    client, url, app, _ = assigned_api
    full_review(client, url)
    before = history(client, url)
    payload = receipt_payload(client, revision=200)
    response = client.post(
        work(url) + "/notification-ack", json=payload, headers=_auth(APPROVER_TOKEN)
    )
    assert response.status_code == 200, response.text
    receipt = response.json()
    assert receipt["assignmentDigest"] == before[-1]["recordDigest"]
    assert receipt["actor"] == "web-approver" and receipt["actorRole"] == "approver"
    assert receipt["acknowledged"] and not receipt["executionAuthorized"]
    assert not receipt["externalDeliveryAuthorized"]
    assert history(client, url) == before
    with TestClient(app()) as restarted:
        assert (
            restarted.post(
                work(url) + "/notification-ack", json=payload, headers=_auth(APPROVER_TOKEN)
            ).json()
            == receipt
        )
        assert restarted.get(
            work(url) + "/notification-receipts", headers=_auth(AUDITOR_TOKEN)
        ).json() == [receipt]
        assert restarted.get(INBOX, headers=_auth(APPROVER_TOKEN)).json()["items"][-1][
            "acknowledged"
        ]
        assert history(restarted, url) == before
        report = restarted.get(url + "/report.md", headers=_auth(AUDITOR_TOKEN)).text
        assert receipt["recordDigest"] in report and "200" in report


@pytest.mark.parametrize(
    "token,code", [(None, 401), (OPERATOR_TOKEN, 409), (AUDITOR_TOKEN, 403), (WORKER_TOKEN, 403)]
)
def test_receipt_authentication_role_and_recipient_boundaries(assigned_api, token, code):
    client, url, _, _ = assigned_api
    assert assign(client, url).status_code == 200
    payload = receipt_payload(client)
    result = client.post(
        work(url) + "/notification-ack", json=payload, headers=_auth(token) if token else {}
    )
    assert result.status_code == code, result.text
    assert len(history(client, url)) == 2


def test_demoted_recipient_cannot_write_receipt(assigned_api):
    client, url, app, _ = assigned_api
    assert assign(client, url).status_code == 200
    payload = receipt_payload(client)
    with TestClient(app(demoted=True)) as reader:
        assert reader.get(NOTICES, headers=_auth(APPROVER_TOKEN)).status_code == 200
        assert (
            reader.post(
                work(url) + "/notification-ack", json=payload, headers=_auth(APPROVER_TOKEN)
            ).status_code
            == 403
        )


@pytest.mark.parametrize("legacy_first", [False, True])
def test_legacy_and_independent_receipts_cannot_double_ack(assigned_api, legacy_first):
    client, url, _, _ = assigned_api
    assert assign(client, url).status_code == 200
    payload = receipt_payload(client)
    legacy = {"requestKey": "legacy", "expectedRevision": 2, "assignmentRevision": 2}
    endpoints = [(url + "/notification-ack", legacy), (work(url) + "/notification-ack", payload)]
    first, second = endpoints if legacy_first else endpoints[::-1]
    saved = client.post(first[0], json=first[1], headers=_auth(APPROVER_TOKEN))
    assert saved.status_code == 200, saved.text
    assert client.post(second[0], json=second[1], headers=_auth(APPROVER_TOKEN)).status_code == 409
    assert (
        client.post(first[0], json=first[1], headers=_auth(APPROVER_TOKEN)).json() == saved.json()
    )


def test_receipt_exact_retry_concurrent_writers_and_identity_mismatch(assigned_api):
    client, url, _, _ = assigned_api
    assert assign(client, url).status_code == 200
    payload = receipt_payload(client)
    endpoint = work(url) + "/notification-ack"
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda _: client.post(endpoint, json=payload, headers=_auth(APPROVER_TOKEN)),
                range(2),
            )
        )
    assert [r.status_code for r in responses] == [200, 200]
    assert responses[0].json() == responses[1].json()
    for change in (
        {"requestKey": "other"},
        {"notificationId": "review-notice_" + "0" * 64},
        {"assignmentRevision": 200},
    ):
        assert (
            client.post(
                endpoint, json={**payload, **change}, headers=_auth(APPROVER_TOKEN)
            ).status_code
            == 409
        )
    assert len(history(client, url)) == 2


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE cp_review_notification_receipts SET actor='changed'",
        "DELETE FROM cp_review_notification_receipts",
        "INSERT OR REPLACE INTO cp_review_notification_receipts "
        "SELECT * FROM cp_review_notification_receipts",
    ],
)
def test_receipt_rows_are_append_only(assigned_api, statement):
    client, url, _, _ = assigned_api
    assert assign(client, url).status_code == 200
    assert (
        client.post(
            work(url) + "/notification-ack",
            json=receipt_payload(client),
            headers=_auth(APPROVER_TOKEN),
        ).status_code
        == 200
    )
    repository = client.app.state.repository
    with pytest.raises(DatabaseError, match="append-only"), repository.engine.begin() as connection:
        connection.exec_driver_sql(statement)
    repository.initialize()
    assert (
        len(client.get(work(url) + "/notification-receipts", headers=_auth(AUDITOR_TOKEN)).json())
        == 1
    )


@pytest.mark.parametrize(
    "column,expression",
    [
        ("payload", "'{}'"),
        ("actor_role", "'operator'"),
        ("assignment_digest", "'" + "a" * 64 + "'"),
    ],
)
def test_corrupt_receipts_refuse_filtered_and_legacy_inboxes_and_report(
    assigned_api, column, expression
):
    client, url, _, _ = assigned_api
    assign(client, url)
    assert (
        client.post(
            work(url) + "/notification-ack",
            json=receipt_payload(client),
            headers=_auth(APPROVER_TOKEN),
        ).status_code
        == 200
    )
    with client.app.state.repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER cp_review_notification_receipts_no_update")
        connection.exec_driver_sql(
            f"UPDATE cp_review_notification_receipts SET {column}={expression}"
        )
    for path in (
        INBOX,
        NOTICES,
        SEARCH + "?state=accepted",
        work(url) + "/notification-receipts",
        url + "/report.md",
    ):
        assert client.get(path, headers=_auth(APPROVER_TOKEN)).status_code == 409, path


def test_full_followup_is_open_retains_original_and_does_not_inherit_acceptance(assigned_api):
    from pajin.control_plane.measured_reviews.models import ReviewEvidence
    from tests.test_measured_reviews import _assessment

    client, url, app, raw = assigned_api
    evidence = ReviewEvidence.model_validate_json(json.dumps(raw))
    assert (
        client.post(
            url + "/assessment",
            headers=_auth(OPERATOR_TOKEN),
            json={
                "requestKey": "assess",
                "expectedRevision": 1,
                "assessment": _assessment(evidence).model_dump(mode="json", by_alias=True),
            },
        ).status_code
        == 200
    )
    assert (
        client.post(
            url + "/decision",
            headers=_auth(APPROVER_TOKEN),
            json={
                "requestKey": "decide",
                "expectedRevision": 2,
                "decision": "accept",
                "reason": "Reviewed",
            },
        ).status_code
        == 200
    )
    full = full_review(client, url)
    assert full["state"] == "accepted"
    before = history(client, url)
    payload = {
        "requestKey": "follow",
        "expectedRevision": 200,
        "expectedDigest": full["recordDigest"],
        "title": "Continued review",
        "reason": "Continue the bounded review",
    }
    response = client.post(work(url) + "/follow-up", json=payload, headers=_auth(OPERATOR_TOKEN))
    assert response.status_code == 200, response.text
    child = response.json()
    assert (
        child["apiVersion"].endswith("/v3") and child["revision"] == 1 and child["state"] == "open"
    )
    assert child["reviewId"] != full["reviewId"] and child["evidence"] == full["evidence"]
    assert child["assessment"] is None and child["decision"] is None and child["retest"] is None
    assert child.get("assignee") is None and child.get("decisionRevision") is None
    assert child["predecessor"] == {
        "reviewId": full["reviewId"],
        "revision": 200,
        "recordDigest": full["recordDigest"],
        "reason": payload["reason"],
    }
    assert history(client, url) == before
    with TestClient(app()) as restarted:
        assert (
            restarted.post(
                work(url) + "/follow-up", json=payload, headers=_auth(OPERATOR_TOKEN)
            ).json()
            == child
        )
        assert (
            restarted.get(BASE + "/" + child["reviewId"], headers=_auth(AUDITOR_TOKEN)).json()
            == child
        )
        report = restarted.get(
            BASE + "/" + child["reviewId"] + "/report.md", headers=_auth(AUDITOR_TOKEN)
        ).text
        assert full["recordDigest"] in report and full["reviewId"] in report
        assert history(restarted, url) == before
        opening = history(restarted, BASE + "/" + child["reviewId"])[0]
        for version in ("v1", "v2"):
            with pytest.raises(ValueError):
                ReviewRevision.model_validate_json(
                    json.dumps(
                        {**opening, "apiVersion": "pajin.dev/measured-review-revision/" + version}
                    )
                )
    with client.app.state.repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER cp_measured_review_revisions_no_update")
        connection.execute(
            text(
                "UPDATE cp_measured_review_revisions SET payload='{}' "
                "WHERE review_id=:id AND revision=1"
            ),
            {"id": full["reviewId"]},
        )
    assert (
        client.get(BASE + "/" + child["reviewId"], headers=_auth(AUDITOR_TOKEN)).status_code == 409
    )


@pytest.mark.parametrize(
    "token,status",
    [(OPERATOR_TOKEN, 409), (APPROVER_TOKEN, 403), (AUDITOR_TOKEN, 403), (WORKER_TOKEN, 403)],
)
def test_followup_refuses_nonfull_or_unprivileged_review(assigned_api, token, status):
    client, url, _, _ = assigned_api
    payload = {
        "requestKey": "follow",
        "expectedRevision": 200,
        "expectedDigest": history(client, url)[0]["recordDigest"],
        "title": "Follow",
        "reason": "Continue",
    }
    response = client.post(work(url) + "/follow-up", json=payload, headers=_auth(token))
    assert response.status_code == status, response.text
    assert len(client.get(BASE, headers=_auth(OPERATOR_TOKEN)).json()["items"]) == 1


def test_filters_and_independent_ack_change_only_personal_unread_state(assigned_api):
    client, url, _, _ = assigned_api
    assert (
        client.get(SEARCH + "?unassigned=true&state=open", headers=_auth(APPROVER_TOKEN)).json()[
            "items"
        ][0]["reviewId"]
        == url.rsplit("/", 1)[-1]
    )
    assert assign(client, url).status_code == 200
    query = "?assignee=web-approver&state=open&unread=true"
    page = client.get(SEARCH + query, headers=_auth(APPROVER_TOKEN)).json()
    assert page["items"][0]["unreadNotifications"] == 1 and page["filters"]["unread"]
    assert client.get(SEARCH + query, headers=_auth(OPERATOR_TOKEN)).json()["items"] == []
    assert (
        client.get(SEARCH + "?unassigned=true", headers=_auth(APPROVER_TOKEN)).json()["items"] == []
    )
    assert len(client.get(NOTICES + query, headers=_auth(APPROVER_TOKEN)).json()["items"]) == 1
    assert (
        client.post(
            work(url) + "/notification-ack",
            json=receipt_payload(client),
            headers=_auth(APPROVER_TOKEN),
        ).status_code
        == 200
    )
    assert client.get(SEARCH + query, headers=_auth(APPROVER_TOKEN)).json()["items"] == []
    assert client.get(NOTICES + query, headers=_auth(APPROVER_TOKEN)).json()["items"] == []
    assert (
        client.get(SEARCH + "?assignee=web-approver", headers=_auth(APPROVER_TOKEN)).json()[
            "items"
        ][0]["revision"]
        == 2
    )


@pytest.mark.parametrize(
    "query,status",
    [
        ("?state=bad", 422),
        ("?assignee=web-approver&unassigned=true", 422),
        ("?state=open&state=accepted", 400),
        ("?limit=100", 400),
        ("?cursor=bad!", 422),
    ],
)
def test_filter_query_rejects_invalid_or_ambiguous_scope(assigned_api, query, status):
    client, _, _, _ = assigned_api
    for path in (SEARCH, NOTICES):
        assert client.get(path + query, headers=_auth(OPERATOR_TOKEN)).status_code == status


def test_empty_filtered_page_continues_and_cursor_is_principal_filter_kind_bound(assigned_api):
    client, _, _, evidence = assigned_api
    for index in range(10):
        response = client.post(
            BASE,
            json={
                "requestKey": f"open-{index}",
                "title": f"Review {index}",
                "domain": "ai",
                "evidenceDigest": evidence["evidenceDigest"],
            },
            headers=_auth(OPERATOR_TOKEN),
        )
        assert response.status_code == 200, response.text
    page = client.get(SEARCH + "?state=accepted", headers=_auth(OPERATOR_TOKEN)).json()
    assert page["scannedReviews"] == 10 and page["items"] == [] and page["nextCursor"]
    cursor = page["nextCursor"]
    final = client.get(
        SEARCH, params={"state": "accepted", "cursor": cursor}, headers=_auth(OPERATOR_TOKEN)
    ).json()
    assert final["scannedReviews"] == 1 and final["nextCursor"] is None
    for path, params, token in [
        (SEARCH, {"cursor": cursor}, OPERATOR_TOKEN),
        (SEARCH, {"state": "accepted", "cursor": cursor}, APPROVER_TOKEN),
        (NOTICES, {"state": "accepted", "cursor": cursor}, OPERATOR_TOKEN),
    ]:
        assert client.get(path, params=params, headers=_auth(token)).status_code == 422
    assert client.get(SEARCH, headers=_auth(WORKER_TOKEN)).status_code == 403


def test_exact_schema16_upgrade_preserves_old_review_bytes_and_installs_receipt_guards(
    assigned_api,
):
    client, url, _, _ = assigned_api
    assert assign(client, url).status_code == 200
    before = history(client, url)
    repository = client.app.state.repository
    with repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE cp_review_notification_receipts")
        connection.exec_driver_sql("DELETE FROM cp_schema_version WHERE version=17")
    assert set(inspect(repository.engine).get_table_names()) == V16_CONTROL_PLANE_TABLES
    repository.initialize()
    repository.initialize()
    assert repository.schema_version() == CURRENT_SCHEMA_VERSION == 17
    assert history(client, url) == before
    assert (
        client.get(work(url) + "/notification-receipts", headers=_auth(OPERATOR_TOKEN)).json() == []
    )
    with repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE cp_review_notification_receipts")
    with pytest.raises(SchemaInitializationError, match="schema-v16"):
        repository.initialize()
    assert "cp_review_notification_receipts" not in inspect(repository.engine).get_table_names()


def test_receipt_byte_preflight_refuses_oversized_stored_json(assigned_api):
    client, url, _, _ = assigned_api
    assign(client, url)
    assert (
        client.post(
            work(url) + "/notification-ack",
            json=receipt_payload(client),
            headers=_auth(APPROVER_TOKEN),
        ).status_code
        == 200
    )
    with client.app.state.repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER cp_review_notification_receipts_no_update")
        connection.execute(
            text("UPDATE cp_review_notification_receipts SET payload=:payload"),
            {"payload": json.dumps({"oversized": "x" * (398 * 4096)})},
        )
    result = client.get(work(url) + "/notification-receipts", headers=_auth(APPROVER_TOKEN))
    assert result.status_code == 409 and "bounded history" in result.text


def test_rehashed_receipt_still_requires_the_original_eligible_recipient(assigned_api):
    from pajin.control_plane.measured_reviews.models import (
        NotificationReceipt,
        NotificationReceiptRequest,
    )
    from pajin.control_plane.measured_reviews.notifications import receipt_request_digest

    client, url, _, _ = assigned_api
    assign(client, url)
    response = client.post(
        work(url) + "/notification-ack", json=receipt_payload(client), headers=_auth(APPROVER_TOKEN)
    )
    assert response.status_code == 200
    raw = response.json()
    raw["actor"] = "web-operator"
    raw["actorRole"] = "operator"
    raw.pop("recordDigest")
    raw["requestDigest"] = receipt_request_digest(
        raw["reviewId"],
        NotificationReceiptRequest(
            requestKey=raw["requestKey"],
            notificationId="review-notice_" + raw["assignmentDigest"],
            assignmentRevision=2,
        ),
        actor="web-operator",
        role="operator",
    )
    forged = NotificationReceipt.model_validate_json(json.dumps(raw))
    with client.app.state.repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER cp_review_notification_receipts_no_update")
        connection.execute(
            text(
                "UPDATE cp_review_notification_receipts SET actor='web-operator', "
                "actor_role='operator', request_digest=:request, "
                "record_digest=:record, payload=:payload"
            ),
            {
                "request": forged.request_digest,
                "record": forged.record_digest,
                "payload": forged.model_dump_json(by_alias=True),
            },
        )
    for endpoint in (INBOX, NOTICES, work(url) + "/notification-receipts"):
        assert client.get(endpoint, headers=_auth(OPERATOR_TOKEN)).status_code == 409


def test_both_reassignment_recipients_can_ack_without_lost_writes(assigned_api):
    client, url, _, _ = assigned_api
    assign(client, url)
    assert (
        assign(client, url, key="other-assignee", expected=2, recipient="web-operator").status_code
        == 200
    )
    payload = receipt_payload(client, revision=3)
    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(
            pool.map(
                lambda token: client.post(
                    work(url) + "/notification-ack", json=payload, headers=_auth(token)
                ),
                [APPROVER_TOKEN, OPERATOR_TOKEN],
            )
        )
    assert [r.status_code for r in replies] == [200, 200]
    assert {r.json()["actor"] for r in replies} == {"web-approver", "web-operator"}
    assert len(history(client, url)) == 3
    for token in (OPERATOR_TOKEN, APPROVER_TOKEN):
        assert client.get(INBOX, headers=_auth(token)).json()["items"][-1]["acknowledged"]


def test_schema17_interrupted_migration_rolls_back_new_table_and_version(assigned_api):
    from sqlalchemy import event

    client, url, _, _ = assigned_api
    repository = client.app.state.repository
    before = history(client, url)
    with repository.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE cp_review_notification_receipts")
        connection.exec_driver_sql("DELETE FROM cp_schema_version WHERE version=17")

    def interrupt(_conn, _cursor, statement, parameters, _context, _many):
        if statement.startswith("INSERT INTO cp_schema_version") and parameters[0] == 17:
            raise RuntimeError("injected schema17 transaction interruption")

    event.listen(repository.engine, "before_cursor_execute", interrupt)
    try:
        with pytest.raises(RuntimeError, match="schema17 transaction interruption"):
            repository.initialize()
    finally:
        event.remove(repository.engine, "before_cursor_execute", interrupt)
    assert set(inspect(repository.engine).get_table_names()) == V16_CONTROL_PLANE_TABLES
    with repository.engine.connect() as connection:
        assert connection.scalar(text("SELECT max(version) FROM cp_schema_version")) == 16
    repository.initialize()
    assert history(client, url) == before


def test_v3_followup_can_be_assessed_and_accepted_through_existing_endpoints(assigned_api):
    from pajin.control_plane.measured_reviews.models import ReviewEvidence
    from tests.test_measured_reviews import _assessment

    client, url, _, raw = assigned_api
    full = full_review(client, url)
    payload = dict(
        requestKey="follow-live",
        expectedRevision=200,
        expectedDigest=full["recordDigest"],
        title="Fresh judgment",
        reason="Continue review",
    )
    stale = client.post(
        work(url) + "/follow-up",
        json={**payload, "expectedDigest": "0" * 64},
        headers=_auth(OPERATOR_TOKEN),
    )
    assert stale.status_code == 409
    response = client.post(work(url) + "/follow-up", json=payload, headers=_auth(OPERATOR_TOKEN))
    assert response.status_code == 200
    child = BASE + "/" + response.json()["reviewId"]
    evidence = ReviewEvidence.model_validate_json(json.dumps(raw))
    assessed = client.post(
        child + "/assessment",
        json=dict(
            requestKey="fresh-assess",
            expectedRevision=1,
            assessment=_assessment(evidence).model_dump(mode="json", by_alias=True),
        ),
        headers=_auth(OPERATOR_TOKEN),
    )
    assert assessed.status_code == 200 and assessed.json()["state"] == "awaiting-review"
    accepted = client.post(
        child + "/decision",
        json=dict(
            requestKey="fresh-accept",
            expectedRevision=2,
            decision="accept",
            reason="Separately reviewed new assessment",
        ),
        headers=_auth(APPROVER_TOKEN),
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["state"] == "accepted" and accepted.json()["decisionRevision"] == 3
    assert accepted.json()["apiVersion"].endswith("/v3")
    assert accepted.json()["predecessor"] == response.json()["predecessor"]


@pytest.mark.parametrize("operation", ["receipt", "followup"])
def test_clock_rollback_refuses_new_records_without_poisoning_retained_history(
    assigned_api, monkeypatch, operation
):
    import pajin.control_plane.measured_reviews.service as service_module

    client, url, _, _ = assigned_api
    if operation == "receipt":
        assign(client, url)
        payload = receipt_payload(client)
        endpoint, token = work(url) + "/notification-ack", APPROVER_TOKEN
    else:
        full = full_review(client, url)
        payload = dict(
            requestKey="clock-followup",
            expectedRevision=200,
            expectedDigest=full["recordDigest"],
            title="Follow",
            reason="Continue",
        )
        endpoint, token = work(url) + "/follow-up", OPERATOR_TOKEN
    before = history(client, url)
    earlier = datetime.fromisoformat(before[-1]["recordedAt"]) - timedelta(seconds=1)

    class RolledBackClock:
        @staticmethod
        def now(_zone):
            return earlier

    monkeypatch.setattr(service_module, "datetime", RolledBackClock)
    result = client.post(endpoint, json=payload, headers=_auth(token))
    assert result.status_code == 409 and "clock precedes" in result.text
    assert history(client, url) == before
    assert (
        client.get(work(url) + "/notification-receipts", headers=_auth(APPROVER_TOKEN)).json() == []
    )
    assert len(client.get(BASE, headers=_auth(OPERATOR_TOKEN)).json()["items"]) == 1
