from __future__ import annotations

import html
import json
import re
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.database import EventRecord, RunRecord
from pajin.control_plane.executors import CampaignJobExecutor, CampaignJobInput
from pajin.control_plane.models import (
    JobKind,
    JobState,
    JobView,
    Principal,
    PrincipalRole,
    RunState,
)

OPERATOR_TOKEN = "web-operator-token-that-is-long-and-distinct"
APPROVER_TOKEN = "web-approver-token-that-is-long-and-distinct"
AUDITOR_TOKEN = "web-auditor-token-that-is-long-and-distinct"
WORKER_TOKEN = "web-worker-token-that-is-long-and-distinct"


def _settings(path: Path) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{path.as_posix()}",
        credentials={
            OPERATOR_TOKEN: Principal(
                subject="web-operator",
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            APPROVER_TOKEN: Principal(
                subject="web-approver",
                roles=frozenset({PrincipalRole.APPROVER}),
            ),
            AUDITOR_TOKEN: Principal(
                subject="web-auditor",
                roles=frozenset({PrincipalRole.AUDITOR}),
            ),
            WORKER_TOKEN: Principal(
                subject="web-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"web-v1": b"web-console-signing-key-32-bytes-minimum"},
        active_checkpoint_key_id="web-v1",
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _submit(client: TestClient, suffix: str, *, marker: str) -> dict[str, object]:
    response = client.post(
        "/v1/runs",
        headers=_auth(OPERATOR_TOKEN),
        json={
            "campaign_name": f"console-{suffix}",
            "input": {"objective": "authorized console validation", "marker": marker},
            "idempotency_key": f"console-submission-{suffix}",
            "max_attempts": 3,
            "job_kind": "campaign",
        },
    )
    assert response.status_code == 200, response.text
    return cast(dict[str, object], response.json())


def _executor_input(markup: str) -> dict[str, object]:
    match = re.search(r'<textarea id="run-input"[^>]*>(.*?)</textarea>', markup, re.DOTALL)
    assert match is not None
    value = json.loads(html.unescape(match.group(1)))
    assert isinstance(value, dict)
    return value


def test_run_list_requires_read_role_and_returns_empty_defaults(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "empty-list.db"))
    with TestClient(app) as client:
        missing = client.get("/v1/runs")
        assert missing.status_code == 401
        assert missing.headers["www-authenticate"] == "Bearer"
        assert "no-store" in missing.headers["cache-control"]

        worker = client.get("/v1/runs", headers=_auth(WORKER_TOKEN))
        assert worker.status_code == 403
        assert client.get("/v1/session", headers=_auth(WORKER_TOKEN)).status_code == 403

        for token in (OPERATOR_TOKEN, APPROVER_TOKEN, AUDITOR_TOKEN):
            response = client.get("/v1/runs", headers=_auth(token))
            assert response.status_code == 200
            assert response.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}

        session = client.get("/v1/session", headers=_auth(OPERATOR_TOKEN))
        assert session.status_code == 200
        assert session.json()["subject"] == "web-operator"
        assert set(session.json()["roles"]) == {"operator", "auditor"}


def test_run_list_is_safely_paginated_filtered_and_stably_sorted(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "run-list.db"))
    with TestClient(app) as client:
        submissions = [
            _submit(client, "alpha", marker="LIST-SECRET-ALPHA"),
            _submit(client, "bravo", marker="LIST-SECRET-BRAVO"),
            _submit(client, "charlie", marker="LIST-SECRET-CHARLIE"),
        ]
        run_ids = [str(cast(dict[str, object], item["run"])["run_id"]) for item in submissions]
        newest = datetime(2026, 7, 14, 8, 0, tzinfo=UTC)
        tied = newest - timedelta(minutes=1)
        with app.state.repository.transaction() as session:
            session.execute(
                update(RunRecord)
                .where(RunRecord.run_id == run_ids[0])
                .values(updated_at=tied, state=RunState.RUNNING.value)
            )
            session.execute(
                update(RunRecord).where(RunRecord.run_id == run_ids[1]).values(updated_at=tied)
            )
            session.execute(
                update(RunRecord).where(RunRecord.run_id == run_ids[2]).values(updated_at=newest)
            )

        first = client.get("/v1/runs?limit=2&offset=0", headers=_auth(AUDITOR_TOKEN))
        assert first.status_code == 200
        first_body = first.json()
        expected = [run_ids[2], *sorted(run_ids[:2], reverse=True)]
        assert [item["run_id"] for item in first_body["items"]] == expected[:2]
        assert first_body["total"] == 3
        assert first_body["limit"] == 2
        assert first_body["offset"] == 0

        second = client.get("/v1/runs?limit=2&offset=2", headers=_auth(AUDITOR_TOKEN))
        assert second.status_code == 200
        assert [item["run_id"] for item in second.json()["items"]] == expected[2:]
        assert second.json()["total"] == 3

        expected_keys = {
            "run_id",
            "campaign_name",
            "state",
            "current_checkpoint_id",
            "created_at",
            "updated_at",
        }
        for item in [*first_body["items"], *second.json()["items"]]:
            assert set(item) == expected_keys
        for marker in ("LIST-SECRET-ALPHA", "LIST-SECRET-BRAVO", "LIST-SECRET-CHARLIE"):
            assert marker not in first.text
            assert marker not in second.text

        running = client.get("/v1/runs?state=running", headers=_auth(APPROVER_TOKEN))
        assert running.status_code == 200
        assert running.json()["total"] == 1
        assert running.json()["items"][0]["run_id"] == run_ids[0]

        detail = client.get(f"/v1/runs/{run_ids[0]}", headers=_auth(AUDITOR_TOKEN))
        assert detail.status_code == 200
        assert detail.json()["input"]["marker"] == "LIST-SECRET-ALPHA"
        events = client.get(f"/v1/runs/{run_ids[0]}/events", headers=_auth(AUDITOR_TOKEN))
        assert events.status_code == 200
        assert events.json()[0]["event_type"] == "run.submitted"

        with app.state.repository.transaction() as session:
            event_count_before = session.scalar(select(func.count()).select_from(EventRecord))
        read_again = client.get("/v1/runs", headers=_auth(OPERATOR_TOKEN))
        assert read_again.status_code == 200
        with app.state.repository.transaction() as session:
            event_count_after = session.scalar(select(func.count()).select_from(EventRecord))
        assert event_count_after == event_count_before

        replay = client.post(
            "/v1/runs",
            headers=_auth(OPERATOR_TOKEN),
            json={
                "campaign_name": "console-alpha",
                "input": {"marker": "IGNORED-REPLAY"},
                "idempotency_key": "console-submission-alpha",
            },
        )
        assert replay.status_code == 409
        assert "idempotency key" in replay.json()["detail"]
        assert client.get("/v1/runs", headers=_auth(OPERATOR_TOKEN)).json()["total"] == 3


@pytest.mark.parametrize(
    ("query", "expected_status"),
    [
        ("limit=1", 200),
        ("limit=100", 200),
        ("offset=0", 200),
        ("offset=10000", 200),
        ("limit=0", 422),
        ("limit=101", 422),
        ("offset=-1", 422),
        ("offset=10001", 422),
        ("state=not-a-state", 422),
    ],
)
def test_run_list_validates_query_bounds(tmp_path: Path, query: str, expected_status: int) -> None:
    app = create_app(_settings(tmp_path / f"bounds-{expected_status}-{query.split('=')[0]}.db"))
    with TestClient(app) as client:
        response = client.get(f"/v1/runs?{query}", headers=_auth(OPERATOR_TOKEN))
    assert response.status_code == expected_status


def test_web_console_shell_and_assets_are_public_but_hardened(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "web-assets.db"))
    with TestClient(app) as client:
        responses = {
            "html": client.get("/ui"),
            "html-slash": client.get("/ui/"),
            "css": client.get("/ui/assets/app.css"),
            "js": client.get("/ui/assets/app.js"),
            "protocol-js": client.get("/ui/assets/protocol.js"),
            "render-js": client.get("/ui/assets/render.js"),
        }
        for response in responses.values():
            assert response.status_code == 200
            assert "no-store" in response.headers["cache-control"]
            assert response.headers["pragma"] == "no-cache"
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["referrer-policy"] == "no-referrer"
            assert response.headers["x-frame-options"] == "DENY"
            assert response.headers["cross-origin-opener-policy"] == "same-origin"
            assert response.headers["cross-origin-resource-policy"] == "same-origin"
            assert "camera=()" in response.headers["permissions-policy"]
            assert "set-cookie" not in response.headers
            assert "access-control-allow-origin" not in response.headers

        assert responses["html"].headers["content-type"].startswith("text/html")
        assert responses["css"].headers["content-type"].startswith("text/css")
        assert responses["js"].headers["content-type"].startswith("text/javascript")
        assert responses["protocol-js"].headers["content-type"].startswith("text/javascript")
        assert responses["render-js"].headers["content-type"].startswith("text/javascript")
        policy = responses["html"].headers["content-security-policy"]
        for directive in (
            "default-src 'none'",
            "script-src 'self'",
            "script-src-attr 'none'",
            "style-src 'self'",
            "style-src-attr 'none'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
            "worker-src 'none'",
        ):
            assert directive in policy

        assert client.get("/ui/assets/missing.js").status_code == 404
        assert client.get("/ui/assets/__init__.py").status_code == 404
        assert client.get("/ui/assets/%2e%2e/api.py").status_code == 404
        assert client.get("/v1/runs").status_code == 401
        assert client.post("/v1/runs", json={}).status_code == 401


def test_web_console_uses_external_assets_and_memory_only_credentials(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "web-source.db"))
    with TestClient(app) as client:
        markup = client.get("/ui").text
        application = client.get("/ui/assets/app.js").text
        protocol = client.get("/ui/assets/protocol.js").text
        rendering = client.get("/ui/assets/render.js").text
        javascript = "\n".join((application, protocol, rendering))

    assert '<link rel="stylesheet" href="/ui/assets/app.css">' in markup
    assert '<link rel="modulepreload" href="/ui/assets/protocol.js">' in markup
    assert '<link rel="modulepreload" href="/ui/assets/render.js">' in markup
    assert '<script type="module" src="/ui/assets/app.js"></script>' in markup
    assert "<style" not in markup
    assert re.search(r"<script(?![^>]+src=)", markup) is None
    assert re.search(r"\son[a-z]+\s*=", markup, re.IGNORECASE) is None
    assert re.search(r'id="token-input"[^>]+type="password"', markup) is not None
    assert re.search(r'id="token-input"[^>]+maxlength="4096"', markup) is not None
    assert re.search(r'id="run-input"[^>]+maxlength="1000000"', markup) is not None
    assert re.search(r'id="discovery-campaign"[^>]+maxlength="80"', markup) is not None
    assert re.search(r'id="discovery-run-id"[^>]+maxlength="29"', markup) is not None
    assert re.search(r'id="graph-campaign"[^>]+maxlength="80"', markup) is not None
    assert re.search(r'id="graph-snapshot-id"[^>]+maxlength="79"', markup) is not None
    assert re.search(r'id="hypothesis-ranking-campaign"[^>]+maxlength="80"', markup) is not None
    assert re.search(r'id="hypothesis-ranking-snapshot-id"[^>]+maxlength="79"', markup) is not None
    assert re.search(r'id="main-content"[^>]+tabindex="-1"', markup) is not None
    assert re.search(r'id="detail-panel"[^>]+aria-busy="false"[^>]+tabindex="-1"', markup)
    assert re.search(r'id="status-message"[^>]+aria-atomic="true"', markup)
    assert '<div class="status-bar">' in markup
    for busy_id in (
        "token-form",
        "run-form",
        "runs-panel",
        "workflow-control",
        "event-list",
        "discovery-panel",
        "discovery-form",
        "graph-panel",
        "graph-form",
        "hypothesis-ranking-panel",
        "hypothesis-ranking-form",
    ):
        assert re.search(rf'id="{busy_id}"[^>]+aria-busy="false"', markup) is not None
    for action_id in (
        "approve-button",
        "deny-button",
        "resume-button",
        "cancel-button",
        "latest-events-button",
        "older-events-button",
        "discovery-load-button",
        "graph-load-button",
        "hypothesis-ranking-load-button",
    ):
        assert re.search(rf'id="{action_id}"[^>]+disabled', markup) is not None
    assert OPERATOR_TOKEN not in markup
    assert APPROVER_TOKEN not in markup
    assert WORKER_TOKEN not in markup

    for forbidden in (
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "document.cookie",
        "innerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "console.",
    ):
        assert forbidden not in javascript
    for required in (
        "textContent",
        "createElement",
        'headers.set("Authorization"',
        'credentials: "omit"',
        'cache: "no-store"',
        'apiRequest("/v1/runs"',
        'apiRequest("/v1/session"',
        "session.canApprove",
        "session.canOperate",
        "StaleRequestError",
        "AbortController",
        "parseJsonPayload",
        "LosslessJsonNumber",
        "resetBusyIndicators",
        "renderDetailFailure",
        "validateJob",
        "validateDiscoveryView",
        "validateCanonicalGraphView",
        "validateHypothesisAttentionRanking",
        "runSubmissionBody",
        "eventPagePath",
        'params.set("before"',
        "encodeURIComponent(approval.approval_id)",
        "encodeURIComponent(approval.checkpoint_id)",
        "encodeURIComponent(run.run_id)",
        "encodeURIComponent(campaign)",
        "encodeURIComponent(runId)",
        "/v1/discovery/campaigns/",
        "/v1/graphs/campaigns/",
        "/v1/hypotheses/campaigns/",
        "/approval`)",
        "/decision`",
        "/resume`",
        "/cancel`",
        "Promise.allSettled",
        "pagehide",
    ):
        assert required in javascript

    assert 'from "./protocol.js"' in application
    assert 'from "./render.js"' in application
    assert 'from "./protocol.js"' in rendering
    assert 'from "./render.js"' not in protocol
    assert 'from "./app.js"' not in protocol + rendering
    assert "document." not in protocol
    assert "globalThis." not in protocol

    executor_input = _executor_input(markup)
    validated = CampaignJobInput.model_validate(executor_input)
    assert validated.profile == "deterministic-local"
    assert validated.manifest.spec.targets[0].type == "mock-sleep"


def test_web_console_runtime_fails_closed_and_discards_stale_responses() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the dependency-free Web Console runtime test")
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            node,
            str(root / "tests" / "js" / "control_plane_web_runtime.mjs"),
            str(root / "src" / "pajin" / "control_plane" / "web" / "app.js"),
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr or result.stdout


@pytest.mark.asyncio
async def test_web_console_default_campaign_executes_through_trusted_adapter(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "web-default-execution.db"))
    with TestClient(app) as client:
        executor_input = _executor_input(client.get("/ui").text)

    now = datetime.now(UTC)
    job = JobView(
        job_id="job_" + "1" * 32,
        run_id="run_" + "1" * 32,
        kind=JobKind.CAMPAIGN,
        state=JobState.LEASED,
        payload={"input": executor_input},
        priority=0,
        attempts=1,
        max_attempts=3,
        available_at=now,
        lease_owner="web-worker",
        lease_expires_at=now + timedelta(seconds=30),
        heartbeat_at=now,
        result=None,
        error=None,
        created_at=now,
        updated_at=now,
    )
    result = await CampaignJobExecutor(output_root=tmp_path / "runs").execute(job)

    assert result.result["engine"] == "local-campaign"
    assert result.result["toolCalls"] == 1
    assert result.result["validatedFindings"] == 0
    assert result.result["confirmedFindings"] == 0
    assert result.result["needsReviewCandidates"] == 0
    report_path = Path(str(result.result["reportPath"]))
    assert report_path.is_file()
    assert "Needs review: `0`" in report_path.read_text(encoding="utf-8")
