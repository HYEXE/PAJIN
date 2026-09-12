"""Atomic assignment, personal inbox, versioned history and acknowledgment boundaries."""

import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pajin.control_plane.api import create_app
from pajin.control_plane.database import MeasuredReviewRevisionRecord
from pajin.control_plane.measured_reviews.models import ReviewEvidence, ReviewRevision
from pajin.control_plane.models import Principal, PrincipalRole
from tests.test_control_plane_web import (
    APPROVER_TOKEN,
    AUDITOR_TOKEN,
    OPERATOR_TOKEN,
    WORKER_TOKEN,
    _auth,
    _settings,
)
from tests.test_measured_review_api import _reader
from tests.test_measured_reviews import _assessment

pytest_plugins = ("tests.test_measured_reviews",)
BASE = "/v1/measured-reviews"
INBOX = "/v1/measured-review-inbox"


@pytest.fixture
def assigned_api(tmp_path, ai_product_context):
    settings = _settings(tmp_path / "assignments.db")

    def app(*, demoted=False):
        configured = settings
        if demoted:
            credentials = dict(settings.credentials)
            credentials[APPROVER_TOKEN] = Principal(
                subject="web-approver", roles=frozenset({PrincipalRole.AUDITOR})
            )
            configured = replace(settings, credentials=credentials)
        return create_app(configured, ai_measured_product_reader=_reader(ai_product_context))

    with TestClient(app()) as client:
        evidence = client.get(
            "/v1/measured-review-evidence/ai", headers=_auth(OPERATOR_TOKEN)
        ).json()
        response = client.post(
            BASE,
            headers=_auth(OPERATOR_TOKEN),
            json={
                "requestKey": "open",
                "domain": "ai",
                "evidenceDigest": evidence["evidenceDigest"],
                "title": "Assignment review",
            },
        )
        assert response.status_code == 200, response.text
        yield client, BASE + "/" + response.json()["reviewId"], app, evidence


def assign(
    client, url, *, key="assign", expected=1, recipient="web-approver", token=OPERATOR_TOKEN
):
    return client.post(
        url + "/assignment",
        headers=_auth(token),
        json={
            "requestKey": key,
            "expectedRevision": expected,
            "assignee": recipient,
            "reason": "Please review the bounded evidence.",
        },
    )


def test_assignment_inbox_ack_restart_and_v1_history_bytes(assigned_api):
    client, url, app, _ = assigned_api
    old = client.get(url + "/history", headers=_auth(OPERATOR_TOKEN)).json()[0]
    roster = client.get("/v1/measured-review-assignees", headers=_auth(OPERATOR_TOKEN))
    assert roster.json() == ["web-approver", "web-operator"]
    result = assign(client, url)
    assert result.status_code == 200, result.text
    assigned = result.json()
    assert assigned["apiVersion"].endswith("/v2") and assigned["state"] == "open"
    assert assigned["assignee"] == "web-approver" and assigned["assignmentRevision"] == 2
    assert not assigned["executionAuthorized"] and not assigned["genericFindingConfirmed"]
    assert assign(client, url).json() == assigned
    assert client.get(INBOX, headers=_auth(OPERATOR_TOKEN)).json()["items"] == []
    notice = client.get(INBOX, headers=_auth(APPROVER_TOKEN)).json()["items"][0]
    assert notice["assignmentRevision"] == 2 and not notice["acknowledged"]
    ack = {"requestKey": "ack", "expectedRevision": 2, "assignmentRevision": 2}
    assert (
        client.post(url + "/notification-ack", json=ack, headers=_auth(OPERATOR_TOKEN)).status_code
        == 409
    )
    saved = client.post(url + "/notification-ack", json=ack, headers=_auth(APPROVER_TOKEN))
    assert saved.status_code == 200, saved.text
    assert saved.json()["revision"] == 3 and saved.json()["state"] == "open"
    assert (
        client.post(url + "/notification-ack", json=ack, headers=_auth(APPROVER_TOKEN)).json()
        == saved.json()
    )
    assert (
        client.post(
            url + "/notification-ack",
            json={**ack, "requestKey": "other-ack", "expectedRevision": 3},
            headers=_auth(APPROVER_TOKEN),
        ).status_code
        == 409
    )
    with TestClient(app()) as restarted:
        inbox = restarted.get(INBOX, headers=_auth(APPROVER_TOKEN)).json()
        assert inbox["items"][0]["acknowledged"] is True
        assert inbox["externalDeliveryAuthorized"] is False
        history = restarted.get(url + "/history", headers=_auth(OPERATOR_TOKEN)).json()
        assert history[0] == old
        assert [r["apiVersion"].rsplit("/", 1)[-1] for r in history] == ["v1", "v2", "v2"]
        downgraded = {**history[1], "apiVersion": "pajin.dev/measured-review-revision/v1"}
        with pytest.raises(ValueError, match="v2"):
            ReviewRevision.model_validate_json(json.dumps(downgraded))


@pytest.mark.parametrize("recipient", ["web-worker", "web-auditor", "not-registered"])
def test_assignment_requires_deployment_registered_reviewer(assigned_api, recipient):
    client, url, _, _ = assigned_api
    assert assign(client, url, recipient=recipient).status_code == 403
    assert client.get(url, headers=_auth(OPERATOR_TOKEN)).json()["revision"] == 1


@pytest.mark.parametrize(
    "token,status", [(APPROVER_TOKEN, 403), (AUDITOR_TOKEN, 403), (WORKER_TOKEN, 403)]
)
def test_only_operator_can_assign(assigned_api, token, status):
    client, url, _, _ = assigned_api
    assert assign(client, url, token=token).status_code == status


def test_reassignment_and_unassignment_notify_both_recipients_without_redeciding(assigned_api):
    client, url, _, raw = assigned_api
    evidence = ReviewEvidence.model_validate_json(json.dumps(raw))
    assessed = client.post(
        url + "/assessment",
        headers=_auth(OPERATOR_TOKEN),
        json={
            "requestKey": "assess",
            "expectedRevision": 1,
            "assessment": _assessment(evidence).model_dump(mode="json", by_alias=True),
        },
    )
    assert assessed.status_code == 200
    accepted = client.post(
        url + "/decision",
        headers=_auth(APPROVER_TOKEN),
        json={
            "requestKey": "decide",
            "expectedRevision": 2,
            "decision": "accept",
            "reason": "Reviewed.",
        },
    )
    assert accepted.status_code == 200
    assigned = assign(client, url, expected=3)
    assert assigned.json()["state"] == "accepted" and assigned.json()["decisionRevision"] == 3
    reassigned = assign(client, url, key="reassign", expected=4, recipient="web-operator")
    assert reassigned.status_code == 200
    assert len(client.get(INBOX, headers=_auth(APPROVER_TOKEN)).json()["items"]) == 2
    assert len(client.get(INBOX, headers=_auth(OPERATOR_TOKEN)).json()["items"]) == 1
    unassigned = assign(client, url, key="remove", expected=5, recipient=None)
    assert unassigned.status_code == 200 and unassigned.json().get("assignee") is None
    report = client.get(url + "/report.md", headers=_auth(AUDITOR_TOKEN))
    assert "Unassigned" in report.text and "Decision recorded at revision 3" in report.text
    assert assign(client, url, key="same", expected=6, recipient=None).status_code == 409


def test_simultaneous_assignments_and_stale_mutations_have_one_winner(assigned_api):
    client, url, _, _ = assigned_api
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda recipient: assign(client, url, key=recipient, recipient=recipient),
                ["web-approver", "web-operator"],
            )
        )
    assert sorted(r.status_code for r in responses) == [200, 409]
    assert client.get(url, headers=_auth(OPERATOR_TOKEN)).json()["revision"] == 2
    assert assign(client, url, key="stale").status_code == 409


@pytest.mark.parametrize("token,status", [(None, 401), (WORKER_TOKEN, 403)])
def test_inbox_and_roster_reject_unauthenticated_and_worker(assigned_api, token, status):
    client, _, _, _ = assigned_api
    for path in (INBOX, "/v1/measured-review-assignees"):
        assert client.get(path, headers=_auth(token) if token else {}).status_code == status


def test_assignment_ui_recovers_from_failed_write_and_discards_old_auth(assigned_api, tmp_path):
    client, url, _, _ = assigned_api
    opened = client.get(url, headers=_auth(OPERATOR_TOKEN)).json()
    assigned = assign(client, url).json()
    unread = client.get(INBOX, headers=_auth(APPROVER_TOKEN)).json()
    acknowledged = client.post(
        url + "/notification-ack",
        headers=_auth(APPROVER_TOKEN),
        json={"requestKey": "ui-ack", "expectedRevision": 2, "assignmentRevision": 2},
    )
    assert acknowledged.status_code == 200
    fixture = tmp_path / "assignment-ui.json"
    fixture.write_text(
        json.dumps(
            dict(
                opened=opened,
                assigned=assigned,
                unread=unread,
                acked=acknowledged.json(),
                read=client.get(INBOX, headers=_auth(APPROVER_TOKEN)).json(),
            )
        )
    )
    node = shutil.which("node")
    assert node is not None, "Node.js is required for browser state verification"
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            node,
            str(root / "tests/js/review_assignment_state.mjs"),
            str(root / "src/pajin/control_plane/web/measured-reviews.js"),
            str(fixture),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "exact retry" in result.stdout


def test_demoted_recipient_can_read_notice_but_cannot_append_acknowledgment(assigned_api):
    client, url, app, _ = assigned_api
    assert assign(client, url).status_code == 200
    with TestClient(app(demoted=True)) as reader:
        inbox = reader.get(INBOX, headers=_auth(APPROVER_TOKEN))
        assert inbox.status_code == 200 and len(inbox.json()["items"]) == 1
        denied = reader.post(
            url + "/notification-ack",
            headers=_auth(APPROVER_TOKEN),
            json={"requestKey": "demoted-ack", "expectedRevision": 2, "assignmentRevision": 2},
        )
        assert denied.status_code == 403
        assert reader.get(url, headers=_auth(APPROVER_TOKEN)).json()["revision"] == 2


def test_last_assignment_and_notifications_remain_readable_at_history_capacity(assigned_api):
    client, url, _, _ = assigned_api
    previous = ReviewRevision.model_validate_json(
        json.dumps(client.get(url + "/history", headers=_auth(OPERATOR_TOKEN)).json()[0])
    )
    rows = []
    for sequence in range(2, 201):
        revision = ReviewRevision.model_validate(
            {
                "apiVersion": "pajin.dev/measured-review-revision/v2",
                "reviewId": previous.review_id,
                "revision": sequence,
                "previousDigest": previous.record_digest,
                "actor": "web-operator",
                "actorRole": "operator",
                "recordedAt": previous.recorded_at,
                "requestKey": f"capacity-{sequence}",
                "requestDigest": f"{sequence:064x}",
                "command": {
                    "action": "assigned",
                    "assignee": "web-approver" if sequence % 2 == 0 else "web-operator",
                    "reason": "Bounded history capacity fixture.",
                },
            }
        )
        rows.append(
            MeasuredReviewRevisionRecord(
                review_id=revision.review_id,
                revision=revision.revision,
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
        previous = revision
    with client.app.state.repository.transaction() as session:
        session.add_all(rows)
    assert client.get(url, headers=_auth(OPERATOR_TOKEN)).json()["revision"] == 200
    inbox = client.get(INBOX, headers=_auth(APPROVER_TOKEN))
    assert inbox.status_code == 200
    assert len(inbox.json()["items"]) == 199
    assert inbox.json()["items"][-1]["assignmentRevision"] == 200
    assert not inbox.json()["items"][-1]["acknowledged"]
