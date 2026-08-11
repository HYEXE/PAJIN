from __future__ import annotations

import asyncio
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event
from time import monotonic
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.exc import DatabaseError

import pajin.control_plane.__main__ as control_plane_main_module
import pajin.control_plane.service as control_plane_service_module
from pajin.control_plane.api import (
    _MAX_CONTROL_PLANE_REQUEST_BODY_BYTES,
    _MAX_CONTROL_PLANE_REQUEST_BODY_CHUNKS,
    ControlPlaneSettings,
    _parse_replay_executor_profiles,
    create_app,
)
from pajin.control_plane.database import (
    ApprovalRecord,
    CheckpointRecord,
    ControlPlaneRepository,
    EventRecord,
    JobRecord,
    RunRecord,
)
from pajin.control_plane.models import (
    CHECKPOINT_STATE_JSON_POLICY,
    COMPLETE_JOB_RESULT_JSON_POLICY,
    SUBMIT_RUN_INPUT_JSON_POLICY,
    ApprovalIntent,
    ClaimJobRequest,
    CompleteJobRequest,
    CreateCheckpointRequest,
    JobKind,
    JobState,
    Principal,
    PrincipalRole,
    ReplayToolPermitRequest,
    ReplayToolPermitView,
    RunState,
    SubmitRunRequest,
    canonical_control_plane_json,
    submission_authority_digest,
)
from pajin.control_plane.security import AuthenticationError, CheckpointSigner, TokenAuthenticator
from pajin.control_plane.service import (
    MAX_AUDIT_EVENT_PAGE_SIZE,
    MAX_AUDIT_EVENT_RESPONSE_BYTES,
    MIN_JOB_HEARTBEAT_EVENT_INTERVAL_SECONDS,
    ControlPlaneService,
    LeaseRejected,
    StateConflict,
)
from pajin.domain.models import ToolRiskTier

OPERATOR_TOKEN = "operator-token-that-is-long-and-distinct"
APPROVER_TOKEN = "approver-token-that-is-long-and-distinct"
WORKER_TOKEN = "worker-token-that-is-long-and-distinct"
REPLAY_WORKER_TOKEN = "replay-worker-token-that-is-long-and-distinct"
OTHER_WORKER_TOKEN = "other-worker-token-that-is-long-and-distinct"


@pytest.mark.parametrize(
    "token",
    [
        "x" * 31,
        "x" * 31 + "\n",
        "x" * 31 + " ",
        "x" * 31 + "é",
        "x" * 4_097,
    ],
    ids=["short", "newline", "space", "non-ascii", "oversize"],
)
def test_token_authenticator_rejects_unsafe_configured_credentials(token: str) -> None:
    principal = Principal(
        subject="worker-service",
        roles=frozenset({PrincipalRole.WORKER}),
    )

    with pytest.raises(ValueError, match="bearer credential"):
        TokenAuthenticator({token: principal})


def test_token_authenticator_accepts_exact_minimum_and_hides_invalid_presented_token() -> None:
    token = "A" * 32
    principal = Principal(
        subject="worker-service",
        roles=frozenset({PrincipalRole.WORKER}),
    )
    authenticator = TokenAuthenticator({token: principal})

    assert authenticator.authenticate(token) == principal
    with pytest.raises(AuthenticationError, match="invalid bearer credential"):
        authenticator.authenticate("x" * 31 + "\n")


@pytest.mark.parametrize(
    "subject",
    [
        "operator\nforged-audit-entry",
        "operator\rforged-audit-entry",
        "operator\x1b[31m",
        "oper\u0430tor",
        "operator/service",
        " operator",
        "operator ",
    ],
    ids=[
        "newline",
        "carriage-return",
        "terminal-control",
        "unicode-confusable",
        "path-separator",
        "leading-space",
        "trailing-space",
    ],
)
def test_principal_subject_rejects_ambiguous_audit_identity(subject: str) -> None:
    with pytest.raises(ValidationError, match="subject"):
        Principal(
            subject=subject,
            roles=frozenset({PrincipalRole.OPERATOR}),
        )


@pytest.mark.parametrize(
    "subject",
    [
        "operator",
        "alice.operator",
        "worker_service-1",
        "oidc:alice@example.com",
        "A" * 200,
    ],
)
def test_principal_subject_accepts_canonical_ascii_identity(subject: str) -> None:
    principal = Principal(
        subject=subject,
        roles=frozenset({PrincipalRole.OPERATOR}),
    )

    assert principal.subject == subject


def _settings(path: Path) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{path.as_posix()}",
        credentials={
            OPERATOR_TOKEN: Principal(
                subject="alice-operator",
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            APPROVER_TOKEN: Principal(
                subject="bob-approver",
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            ),
            WORKER_TOKEN: Principal(
                subject="worker-service",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"test-v1": b"test-checkpoint-signing-key-32-bytes-minimum"},
        active_checkpoint_key_id="test-v1",
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _set_required_control_plane_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "test-checkpoint-signing-key-32-bytes-minimum",
    )


def _replay_tool_permit_view() -> ReplayToolPermitView:
    issued_at = datetime.now(UTC)
    return ReplayToolPermitView(
        permit_id=f"replay-permit_{'8' * 32}",
        permit_digest="c" * 64,
        replay_request_id=f"tool_replay_{'9' * 32}",
        job_id=f"job_{'4' * 32}",
        batch_id=f"replay-batch_{'1' * 32}",
        item_id=f"replay-item_{'2' * 32}",
        ticket_id=f"replay-ticket_{'3' * 32}",
        compilation_id=f"replay-compilation_{'5' * 32}",
        budget_reservation_id=f"budget-reservation_{'6' * 32}",
        rate_reservation_id=f"rate-reservation_{'7' * 32}",
        replay_run_id="run_replay_transport",
        attempt=1,
        fencing_value=7,
        call_ordinal=1,
        issued_to="worker-service",
        executor_profile="kisa-exact-v1",
        source_root_digest="a" * 64,
        compilation_digest="e" * 64,
        grant_digest="f" * 64,
        original_request_id="tool_original_request",
        tool_id="ai.chat-probe",
        tool_version="1.0.0",
        target_id="target-ai-chat",
        target="http://127.0.0.1:8080/v1/chat",
        method="POST",
        compiled_argument_digest="b" * 64,
        tool_call_units=1,
        request_units=3,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=15),
    )


def _submit_request(input_value: dict[str, Any]) -> SubmitRunRequest:
    return SubmitRunRequest(
        campaign_name="bounded-json",
        input=input_value,
        idempotency_key="bounded-json-request",
    )


@pytest.mark.parametrize(
    "number",
    [float("nan"), float("inf"), float("-inf")],
    ids=["nan", "positive-infinity", "negative-infinity"],
)
def test_control_plane_json_rejects_non_finite_numbers(number: float) -> None:
    with pytest.raises(ValidationError, match="must be finite"):
        _submit_request({"number": number})

    with pytest.raises(ValidationError, match="must be finite"):
        CompleteJobRequest(
            worker_id="worker-1",
            lease_token="l" * 32,
            result={"number": number},
        )


def test_control_plane_json_rejects_non_string_keys_cycles_and_invalid_unicode() -> None:
    with pytest.raises(ValidationError, match="keys must be strings"):
        _submit_request({1: "not-json"})  # type: ignore[dict-item]

    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(ValidationError, match="cannot contain cycles"):
        _submit_request({"cycle": cyclic})

    with pytest.raises(ValidationError, match="invalid UTF-8"):
        _submit_request({"text": "\ud800"})


def test_control_plane_json_rejects_depth_node_byte_and_integer_overflow() -> None:
    nested: dict[str, Any] = {}
    for _ in range(33):
        nested = {"nested": nested}
    with pytest.raises(ValidationError, match="nesting-depth limit"):
        _submit_request(nested)

    with pytest.raises(ValidationError, match="node-count limit"):
        _submit_request({"nodes": [None] * 50_000})

    with pytest.raises(ValidationError, match="canonical byte limit"):
        _submit_request({"bytes": "x" * 1_000_000})

    with pytest.raises(ValidationError, match="signed 64-bit range"):
        _submit_request({"integer": 2**63})


def test_submit_json_resource_boundaries_are_exact() -> None:
    nested: dict[str, Any] = {}
    for _ in range(SUBMIT_RUN_INPUT_JSON_POLICY.max_depth):
        nested = {"nested": nested}
    _submit_request(nested)
    with pytest.raises(ValidationError, match="nesting-depth limit"):
        _submit_request({"nested": nested})

    valid_nodes = SUBMIT_RUN_INPUT_JSON_POLICY.max_nodes - 2
    _submit_request({"nodes": [None] * valid_nodes})
    with pytest.raises(ValidationError, match="node-count limit"):
        _submit_request({"nodes": [None] * (valid_nodes + 1)})

    valid_keys = {f"key-{index}": None for index in range(10_000)}
    _submit_request(valid_keys)
    with pytest.raises(ValidationError, match="key-count limit"):
        _submit_request({**valid_keys, "one-key-too-many": None})

    with pytest.raises(ValidationError, match="key byte limit"):
        _submit_request({"k" * 1_025: None})
    with pytest.raises(ValidationError, match="string byte limit"):
        _submit_request({"value": "x" * (SUBMIT_RUN_INPUT_JSON_POLICY.max_string_bytes + 1)})


def test_each_mutation_json_field_accepts_exact_byte_limit_and_rejects_plus_one() -> None:
    def boundary_value(max_bytes: int, *, extra_bytes: int = 0) -> dict[str, str]:
        envelope_bytes = len(canonical_control_plane_json({"value": ""}))
        return {"value": "x" * (max_bytes - envelope_bytes + extra_bytes)}

    submit_value = boundary_value(SUBMIT_RUN_INPUT_JSON_POLICY.max_bytes)
    _submit_request(submit_value)
    with pytest.raises(ValidationError, match="canonical byte limit"):
        _submit_request(boundary_value(SUBMIT_RUN_INPUT_JSON_POLICY.max_bytes, extra_bytes=1))

    CompleteJobRequest(
        worker_id="worker-1",
        lease_token="l" * 32,
        result=boundary_value(COMPLETE_JOB_RESULT_JSON_POLICY.max_bytes),
    )
    with pytest.raises(ValidationError, match="canonical byte limit"):
        CompleteJobRequest(
            worker_id="worker-1",
            lease_token="l" * 32,
            result=boundary_value(
                COMPLETE_JOB_RESULT_JSON_POLICY.max_bytes,
                extra_bytes=1,
            ),
        )

    pending_intent = ApprovalIntent(
        call_fingerprint="a" * 64,
        tool_id="bounded-tool",
        target="https://target.invalid",
        risk_tier=ToolRiskTier.T3,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    CreateCheckpointRequest(
        worker_id="worker-1",
        lease_token="l" * 32,
        state=boundary_value(CHECKPOINT_STATE_JSON_POLICY.max_bytes),
        pending_intent=pending_intent,
    )
    with pytest.raises(ValidationError, match="canonical byte limit"):
        CreateCheckpointRequest(
            worker_id="worker-1",
            lease_token="l" * 32,
            state=boundary_value(
                CHECKPOINT_STATE_JSON_POLICY.max_bytes,
                extra_bytes=1,
            ),
            pending_intent=pending_intent,
        )


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        (
            b'{"campaign_name":"duplicates","input":{},'
            b'"idempotency_key":"duplicate-key-a",'
            b'"idempotency_key":"duplicate-key-b"}',
            "application/json",
        ),
        (
            b'{"campaign_name":"duplicates","input":{"nested":1,"nested":2},'
            b'"idempotency_key":"duplicate-nested"}',
            "application/json; charset=utf-8",
        ),
        (
            b'{"campaign_name":"duplicates","input":{"a":1,"\\u0061":2},'
            b'"idempotency_key":"duplicate-escaped"}',
            "application/vnd.pajin+json; charset=utf-8",
        ),
    ],
    ids=["top-level", "nested", "escaped-equivalent"],
)
def test_mutation_json_rejects_duplicate_member_names_before_persistence(
    tmp_path: Path,
    body: bytes,
    content_type: str,
) -> None:
    app = create_app(_settings(tmp_path / "duplicate-json-members.db"))
    with TestClient(app) as client:
        response = client.post(
            "/v1/runs",
            headers={**_auth(OPERATOR_TOKEN), "Content-Type": content_type},
            content=body,
        )
        assert response.status_code == 422
        assert response.json() == {"detail": "JSON object member names must be unique"}
        with app.state.repository.transaction() as session:
            assert session.scalars(select(RunRecord)).all() == []


def test_duplicate_key_pass_preserves_malformed_empty_and_read_only_contracts(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "duplicate-json-compatibility.db"))
    with TestClient(app) as client:
        malformed = client.post(
            "/v1/runs",
            headers={**_auth(OPERATOR_TOKEN), "Content-Type": "application/json"},
            content=b'{"campaign_name":',
        )
        empty = client.post(
            "/v1/runs",
            headers={**_auth(OPERATOR_TOKEN), "Content-Type": "application/json"},
            content=b"",
        )
        listing = client.get("/v1/runs", headers=_auth(OPERATOR_TOKEN))

    assert malformed.status_code == 422
    assert malformed.json().get("detail") != "JSON object member names must be unique"
    assert empty.status_code == 422
    assert empty.json().get("detail") != "JSON object member names must be unique"
    assert listing.status_code == 200


def test_deep_wire_json_fails_as_a_controlled_client_error(tmp_path: Path) -> None:
    nested = '{"nested":' * 2_000 + "{}" + "}" * 2_000
    body = (
        '{"campaign_name":"deep-wire-json","input":'
        + nested
        + ',"idempotency_key":"deep-wire-json"}'
    )
    app = create_app(_settings(tmp_path / "deep-wire-json.db"))

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/v1/runs",
            headers={**_auth(OPERATOR_TOKEN), "Content-Type": "application/json"},
            content=body,
        )

    assert response.status_code == 422


def test_checkpoint_signer_uses_the_same_bounded_canonical_json_contract() -> None:
    signer = CheckpointSigner(
        active_key_id="test-v1",
        keys={"test-v1": b"test-checkpoint-signing-key-32-bytes-minimum"},
    )
    assert signer.canonical_json({"z": "한글", "a": [1, True, None]}) == (
        '{"a":[1,true,null],"z":"한글"}'.encode()
    )
    with pytest.raises(ValueError, match="must be finite"):
        signer.canonical_json({"number": float("nan")})


def test_submit_run_api_rejects_nonstandard_nan_before_database_persistence(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "bounded-json-api.db"))
    with TestClient(app) as client:
        response = client.post(
            "/v1/runs",
            headers={**_auth(OPERATOR_TOKEN), "Content-Type": "application/json"},
            content=(
                '{"campaign_name":"bounded-json","input":{"number":NaN},'
                '"idempotency_key":"bounded-json-api"}'
            ),
        )
        assert response.status_code == 422
        assert "must be finite" in response.text


@pytest.mark.asyncio
async def test_control_plane_rejects_declared_oversize_before_receiving_body(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "declared-body-limit.db"))
    receive_calls = 0
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal receive_calls
        receive_calls += 1
        raise AssertionError("oversized declared body must not be received")

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/runs",
            "raw_path": b"/v1/runs",
            "query_string": b"",
            "root_path": "",
            "headers": [
                (
                    b"content-length",
                    str(_MAX_CONTROL_PLANE_REQUEST_BODY_BYTES + 1).encode(),
                )
            ],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "state": {},
        },
        receive,
        send,
    )

    assert receive_calls == 0
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413
    assert (b"connection", b"close") in sent[0]["headers"]
    assert b"request body exceeds" in sent[1]["body"]


@pytest.mark.asyncio
async def test_control_plane_request_body_deadline_is_absolute_and_closes_connection(
    tmp_path: Path,
) -> None:
    settings = replace(
        _settings(tmp_path / "body-deadline.db"),
        request_body_timeout_seconds=0.1,
    )
    app = create_app(settings)
    receive_calls = 0
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal receive_calls
        receive_calls += 1
        await asyncio.sleep(0.04)
        return {
            "type": "http.request",
            "body": b"x",
            "more_body": True,
        }

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/runs",
            "raw_path": b"/v1/runs",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"transfer-encoding", b"chunked")],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "state": {},
        },
        receive,
        send,
    )

    assert receive_calls >= 2
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 408
    assert (b"connection", b"close") in sent[0]["headers"]
    assert b"not completed before the deadline" in sent[1]["body"]


def test_control_plane_server_concurrency_limit_is_bounded_and_configurable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_LIMIT_CONCURRENCY", "17")
    assert control_plane_main_module._limit_concurrency_from_env() == 17

    monkeypatch.setenv("PAJIN_CP_LIMIT_CONCURRENCY", "0")
    with pytest.raises(ValueError, match="between 1 and 100000"):
        control_plane_main_module._limit_concurrency_from_env()


@pytest.mark.asyncio
async def test_control_plane_enforces_actual_chunked_body_limit_before_authentication(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "chunked-body-limit.db"))
    receive_calls = 0
    sent: list[dict[str, Any]] = []
    one_mebibyte = b"x" * (1024 * 1024)

    async def receive() -> dict[str, Any]:
        nonlocal receive_calls
        receive_calls += 1
        if receive_calls <= 5:
            return {
                "type": "http.request",
                "body": one_mebibyte,
                "more_body": True,
            }
        raise AssertionError("body fence consumed data after crossing its limit")

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/runs",
            "raw_path": b"/v1/runs",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"content-type", b"application/json")],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "state": {},
        },
        receive,
        send,
    )

    assert receive_calls == 5
    assert sent[0]["status"] == 413
    assert (b"connection", b"close") in sent[0]["headers"]


@pytest.mark.asyncio
async def test_control_plane_bounds_zero_length_request_chunks(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "request-chunk-limit.db"))
    receive_calls = 0
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal receive_calls
        receive_calls += 1
        return {"type": "http.request", "body": b"", "more_body": True}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/runs",
            "raw_path": b"/v1/runs",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"content-type", b"application/json")],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "state": {},
        },
        receive,
        send,
    )

    assert receive_calls == _MAX_CONTROL_PLANE_REQUEST_BODY_CHUNKS + 1
    assert sent[0]["status"] == 413
    assert (b"connection", b"close") in sent[0]["headers"]


def test_control_plane_body_limit_allows_maximum_canonical_json_with_wire_escaping(
    tmp_path: Path,
) -> None:
    # Supplementary Unicode can take twelve ASCII bytes on the wire but only
    # four UTF-8 bytes in the model's canonical representation.
    input_value = {"text": "\U0001f600" * 249_980}
    body = json.dumps(
        {
            "campaign_name": "bounded-wire-envelope",
            "input": input_value,
            "idempotency_key": "bounded-wire-envelope",
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode()
    assert 2_900_000 < len(body) < _MAX_CONTROL_PLANE_REQUEST_BODY_BYTES

    app = create_app(_settings(tmp_path / "bounded-wire-envelope.db"))
    with TestClient(app) as client:
        response = client.post(
            "/v1/runs",
            headers={**_auth(OPERATOR_TOKEN), "Content-Type": "application/json"},
            content=body,
        )

    assert response.status_code == 200, response.text


def _submit(client: TestClient, suffix: str = "main") -> tuple[str, str]:
    response = client.post(
        "/v1/runs",
        headers=_auth(OPERATOR_TOKEN),
        json={
            "campaign_name": "control-plane-lab",
            "input": {"objective": "authorized validation"},
            "idempotency_key": f"control-plane-{suffix}",
            "max_attempts": 3,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return str(body["run"]["run_id"]), str(body["job"]["job_id"])


def _claim(client: TestClient, worker_id: str = "worker-1") -> dict[str, object]:
    response = client.post(
        "/v1/worker/jobs/claim",
        headers=_auth(WORKER_TOKEN),
        json={"worker_id": worker_id, "kinds": ["campaign"], "lease_seconds": 30},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _checkpoint(
    client: TestClient,
    job_id: str,
    lease_token: str,
    *,
    fingerprint: str = "a" * 64,
    risk_tier: int = 3,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    response = client.post(
        f"/v1/worker/jobs/{job_id}/checkpoints",
        headers=_auth(WORKER_TOKEN),
        json={
            "worker_id": "worker-1",
            "lease_token": lease_token,
            "state": {"turn": 4, "messages": ["bounded state"]},
            "pending_intent": {
                "call_fingerprint": fingerprint,
                "tool_id": "mock.approval-probe",
                "target": "lab://approval-check",
                "risk_tier": risk_tier,
                "expires_at": (expires_at or datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
            },
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_human_review_queue_prioritizes_existing_active_authority_without_mutation(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "human-review-queue.db"))
    with TestClient(app) as client:
        pending_run, pending_job = _submit(client, "review-pending")
        pending_claim = _claim(client)
        pending = _checkpoint(
            client,
            pending_job,
            str(pending_claim["lease_token"]),
            risk_tier=4,
            expires_at=datetime.now(UTC) + timedelta(minutes=4),
        )

        approved_run, approved_job = _submit(client, "review-approved")
        approved_claim = _claim(client)
        approved = _checkpoint(
            client,
            approved_job,
            str(approved_claim["lease_token"]),
            expires_at=datetime.now(UTC) + timedelta(minutes=6),
        )
        approved_id = str(approved["approval"]["approval_id"])
        decision = client.post(
            f"/v1/approvals/{approved_id}/decision",
            headers=_auth(APPROVER_TOKEN),
            json={"approve": True, "reason": "bounded queue ordering check"},
        )
        assert decision.status_code == 200, decision.text

        running_run, _running_job = _submit(client, "review-running")
        _claim(client)
        queued_run, _queued_job = _submit(client, "review-queued")

        with app.state.repository.read_transaction() as session:
            events_before = session.scalar(select(func.count()).select_from(EventRecord))
        response = client.get(
            "/v1/review-queue?limit=4",
            headers=_auth(OPERATOR_TOKEN),
        )
        with app.state.repository.read_transaction() as session:
            events_after = session.scalar(select(func.count()).select_from(EventRecord))

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["api_version"] == "pajin.control-plane.human-review-queue/v1"
        assert body["limit"] == 4
        assert body["has_more"] is False
        assert [item["run_id"] for item in body["items"]] == [
            pending_run,
            approved_run,
            running_run,
            queued_run,
        ]
        assert [item["attention"] for item in body["items"]] == [
            "approval-required",
            "resume-required",
            "execution-active",
            "execution-active",
        ]
        assert body["items"][0]["approval"] == {
            "approval_id": pending["approval"]["approval_id"],
            "state": "pending",
            "requested_by": "worker-service",
            "requested_at": pending["approval"]["requested_at"],
            "tool_id": "mock.approval-probe",
            "target": "lab://approval-check",
            "risk_tier": 4,
            "expires_at": pending["approval"]["intent"]["expires_at"],
        }
        assert all(item["kill_switch_candidate"] is True for item in body["items"])
        assert body["authority"] == {
            "queue_snapshot_only": True,
            "approval_decision_authority": False,
            "checkpoint_resume_authority": False,
            "cancellation_authority": False,
            "execution_authority": False,
        }
        assert "call_fingerprint" not in response.text
        assert "authorized validation" not in response.text
        assert events_after == events_before

        bounded = client.get("/v1/review-queue?limit=2", headers=_auth(APPROVER_TOKEN))
        assert bounded.status_code == 200
        assert bounded.json()["has_more"] is True
        assert [item["run_id"] for item in bounded.json()["items"]] == [
            pending_run,
            approved_run,
        ]
        assert client.get("/v1/review-queue", headers=_auth(WORKER_TOKEN)).status_code == 403
        invalid_limit = client.get(
            "/v1/review-queue?limit=0",
            headers=_auth(OPERATOR_TOKEN),
        )
        assert invalid_limit.status_code == 422
        assert (
            client.get("/v1/review-queue?limit=101", headers=_auth(OPERATOR_TOKEN)).status_code
            == 422
        )


def test_human_review_queue_marks_expiry_without_rewriting_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(_settings(tmp_path / "human-review-expiry.db"))
    with TestClient(app) as client:
        run_id, job_id = _submit(client, "review-expired")
        claim = _claim(client)
        expires_at = datetime.now(UTC) + timedelta(minutes=2)
        created = _checkpoint(
            client,
            job_id,
            str(claim["lease_token"]),
            expires_at=expires_at,
        )
        approval_id = str(created["approval"]["approval_id"])
        monkeypatch.setattr(
            control_plane_service_module,
            "utc_now",
            lambda: expires_at + timedelta(seconds=1),
        )
        with app.state.repository.read_transaction() as session:
            events_before = session.scalar(select(func.count()).select_from(EventRecord))

        response = client.get("/v1/review-queue", headers=_auth(OPERATOR_TOKEN))

        assert response.status_code == 200, response.text
        assert response.json()["items"][0]["attention"] == "approval-expired"
        with app.state.repository.read_transaction() as session:
            approval_state = session.scalar(
                select(ApprovalRecord.state).where(ApprovalRecord.approval_id == approval_id)
            )
            run_state = session.scalar(select(RunRecord.state).where(RunRecord.run_id == run_id))
            events_after = session.scalar(select(func.count()).select_from(EventRecord))
        assert approval_state == "pending"
        assert run_state == "awaiting-approval"
        assert events_after == events_before


def test_human_review_queue_fails_closed_on_tampered_approval_binding(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "human-review-tamper.db"))
    with TestClient(app) as client:
        _run_id, job_id = _submit(client, "review-tamper")
        claim = _claim(client)
        created = _checkpoint(client, job_id, str(claim["lease_token"]))
        approval_id = str(created["approval"]["approval_id"])
        with app.state.repository.transaction() as session:
            session.execute(
                update(ApprovalRecord)
                .where(ApprovalRecord.approval_id == approval_id)
                .values(tool_id="mock.substituted-tool")
            )

        response = client.get("/v1/review-queue", headers=_auth(OPERATOR_TOKEN))

    assert response.status_code == 409
    assert "approval fields" in response.json()["detail"]


def test_audit_event_api_returns_bounded_latest_page_with_exclusive_cursor(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "bounded-event-page.db"))
    with TestClient(app) as client:
        run_id, _job_id = _submit(client, "bounded-event-page")
        repository = app.state.repository
        with repository.transaction() as session:
            first_sequence = repository.next_event_sequence(session, run_id)
            for offset in range(240):
                sequence = first_sequence + offset
                session.add(
                    EventRecord(
                        event_id=f"event_bulk_{sequence:032x}",
                        run_id=run_id,
                        sequence=sequence,
                        event_type="bulk.bounded",
                        actor="bounded-test",
                        payload={"sequence": sequence, "blob": "x" * 30_000},
                        occurred_at=datetime.now(UTC),
                    )
                )

        response = client.get(
            f"/v1/runs/{run_id}/events",
            headers=_auth(OPERATOR_TOKEN),
        )
        assert response.status_code == 200, response.text
        latest = response.json()
        latest_sequences = [event["sequence"] for event in latest]
        final_sequence = first_sequence + 239
        assert 1 < len(latest) < MAX_AUDIT_EVENT_PAGE_SIZE
        assert latest_sequences == list(
            range(final_sequence - len(latest_sequences) + 1, final_sequence + 1)
        )
        assert len(response.content) <= MAX_AUDIT_EVENT_RESPONSE_BYTES

        older = client.get(
            f"/v1/runs/{run_id}/events",
            headers=_auth(OPERATOR_TOKEN),
            params={"limit": 25, "before": latest_sequences[0]},
        )
        assert older.status_code == 200, older.text
        older_sequences = [event["sequence"] for event in older.json()]
        assert older_sequences == list(
            range(latest_sequences[0] - len(older_sequences), latest_sequences[0])
        )
        assert len(older_sequences) == 25

        invalid_limit = client.get(
            f"/v1/runs/{run_id}/events",
            headers=_auth(OPERATOR_TOKEN),
            params={"limit": MAX_AUDIT_EVENT_PAGE_SIZE + 1},
        )
        assert invalid_limit.status_code == 422

        for invalid_before in (0, 2_147_483_648):
            invalid_cursor = client.get(
                f"/v1/runs/{run_id}/events",
                headers=_auth(OPERATOR_TOKEN),
                params={"before": invalid_before},
            )
            assert invalid_cursor.status_code == 422

        operation = client.get("/openapi.json").json()["paths"]["/v1/runs/{run_id}/events"]["get"]
        parameters = {parameter["name"]: parameter for parameter in operation["parameters"]}
        assert parameters["limit"]["schema"] == {
            "type": "integer",
            "maximum": MAX_AUDIT_EVENT_PAGE_SIZE,
            "minimum": 1,
            "default": MAX_AUDIT_EVENT_PAGE_SIZE,
            "title": "Limit",
        }
        assert parameters["before"]["schema"] == {
            "anyOf": [
                {"type": "integer", "maximum": 2_147_483_647, "minimum": 1},
                {"type": "null"},
            ],
            "title": "Before",
        }
        response_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
        assert response_schema["type"] == "array"
        assert response_schema["items"] == {"$ref": "#/components/schemas/AuditEventView"}


def test_artifact_repository_environment_requires_both_roots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "test-checkpoint-signing-key-32-bytes-minimum",
    )
    monkeypatch.setenv("PAJIN_CP_ARTIFACT_STAGING_ROOT", "/tmp/pajin-staging")

    with pytest.raises(RuntimeError, match="must be configured together"):
        ControlPlaneSettings.from_env()


@pytest.mark.parametrize(
    "token",
    ["x" * 31 + "\n", "x" * 31 + "é", "x" * 4_097],
    ids=["newline", "non-ascii", "oversize"],
)
def test_control_plane_environment_rejects_unsafe_bearer_credentials(
    monkeypatch: pytest.MonkeyPatch,
    token: str,
) -> None:
    _set_required_control_plane_environment(monkeypatch)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", token)

    with pytest.raises(ValueError, match="bearer credential"):
        ControlPlaneSettings.from_env()


def test_artifact_repository_environment_loads_private_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "test-checkpoint-signing-key-32-bytes-minimum",
    )
    staging_root = tmp_path / "staging"
    repository_root = tmp_path / "repository"
    monkeypatch.setenv("PAJIN_CP_ARTIFACT_STAGING_ROOT", str(staging_root))
    monkeypatch.setenv("PAJIN_CP_ARTIFACT_REPOSITORY_ROOT", str(repository_root))

    settings = ControlPlaneSettings.from_env()

    assert settings.artifact_staging_root == staging_root
    assert settings.artifact_repository_root == repository_root


@pytest.mark.parametrize(
    ("environment_name", "attribute_name", "raw", "expected"),
    [
        ("PAJIN_CP_INITIALIZE_SCHEMA", "initialize_schema", "1", True),
        ("PAJIN_CP_INITIALIZE_SCHEMA", "initialize_schema", "true", True),
        ("PAJIN_CP_INITIALIZE_SCHEMA", "initialize_schema", "YES", True),
        ("PAJIN_CP_INITIALIZE_SCHEMA", "initialize_schema", "0", False),
        ("PAJIN_CP_INITIALIZE_SCHEMA", "initialize_schema", "false", False),
        ("PAJIN_CP_INITIALIZE_SCHEMA", "initialize_schema", "NO", False),
        ("PAJIN_CP_DATABASE_ECHO", "database_echo", "1", True),
        ("PAJIN_CP_DATABASE_ECHO", "database_echo", "False", False),
    ],
)
def test_control_plane_boolean_environment_accepts_only_explicit_tokens(
    monkeypatch: pytest.MonkeyPatch,
    environment_name: str,
    attribute_name: str,
    raw: str,
    expected: bool,
) -> None:
    _set_required_control_plane_environment(monkeypatch)
    monkeypatch.setenv(environment_name, raw)

    settings = ControlPlaneSettings.from_env()

    assert getattr(settings, attribute_name) is expected


@pytest.mark.parametrize(
    "raw",
    ["", "treu", "on", "2", " true", "true ", "\tfalse", "no\n"],
)
@pytest.mark.parametrize(
    "environment_name",
    ["PAJIN_CP_INITIALIZE_SCHEMA", "PAJIN_CP_DATABASE_ECHO"],
)
def test_control_plane_boolean_environment_rejects_typos_and_whitespace(
    monkeypatch: pytest.MonkeyPatch,
    environment_name: str,
    raw: str,
) -> None:
    _set_required_control_plane_environment(monkeypatch)
    monkeypatch.setenv(environment_name, raw)

    with pytest.raises(ValueError, match=environment_name):
        ControlPlaneSettings.from_env()


@pytest.mark.parametrize("field_name", ["initialize_schema", "database_echo"])
def test_programmatic_control_plane_boolean_flags_require_actual_booleans(
    tmp_path: Path,
    field_name: str,
) -> None:
    with pytest.raises(ValueError, match="must be booleans"):
        replace(
            _settings(tmp_path / f"invalid-{field_name}.db"),
            **{field_name: "false"},
        )


def test_create_app_rejects_partial_artifact_repository_configuration(
    tmp_path: Path,
) -> None:
    settings = replace(
        _settings(tmp_path / "control-plane.db"),
        artifact_staging_root=tmp_path / "staging",
    )

    with pytest.raises(RuntimeError, match="must be configured together"):
        create_app(settings)


def test_authenticated_submit_approval_resume_and_completion(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "control-plane.db"))
    with TestClient(app) as client:
        unauthorized = client.post(
            "/v1/runs",
            json={
                "campaign_name": "control-plane-lab",
                "idempotency_key": "missing-auth-key",
            },
        )
        assert unauthorized.status_code == 401

        run_id, job_id = _submit(client)
        duplicate = client.post(
            "/v1/runs",
            headers=_auth(OPERATOR_TOKEN),
            json={
                "campaign_name": "control-plane-lab",
                "input": {"objective": "authorized validation"},
                "idempotency_key": "control-plane-main",
                "max_attempts": 3,
            },
        )
        assert duplicate.status_code == 200
        assert duplicate.json()["created"] is False
        assert duplicate.json()["run"]["run_id"] == run_id
        conflicting_duplicate = client.post(
            "/v1/runs",
            headers=_auth(OPERATOR_TOKEN),
            json={
                "campaign_name": "control-plane-lab",
                "input": {"substituted": "idempotency-authority"},
                "idempotency_key": "control-plane-main",
                "max_attempts": 3,
            },
        )
        assert conflicting_duplicate.status_code == 409
        assert "idempotency key" in conflicting_duplicate.json()["detail"]

        claimed = _claim(client)
        assert claimed["job"]["job_id"] == job_id
        lease_token = str(claimed["lease_token"])
        heartbeat = client.post(
            f"/v1/worker/jobs/{job_id}/heartbeat",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "worker-1",
                "lease_token": lease_token,
                "lease_seconds": 45,
            },
        )
        assert heartbeat.status_code == 200

        created = _checkpoint(client, job_id, lease_token)
        checkpoint_id = str(created["checkpoint"]["checkpoint_id"])
        approval_id = str(created["approval"]["approval_id"])
        assert created["approval"]["state"] == "pending"

        wrong_role = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=_auth(OPERATOR_TOKEN),
            json={"approve": True, "reason": "operator cannot self-approve"},
        )
        assert wrong_role.status_code == 403

        approved = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=_auth(APPROVER_TOKEN),
            json={"approve": True, "reason": "authorized lab scope verified"},
        )
        assert approved.status_code == 200
        assert approved.json()["decided_by"] == "bob-approver"

        worker_cannot_resume = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume",
            headers=_auth(WORKER_TOKEN),
            json={"approval_id": approval_id},
        )
        assert worker_cannot_resume.status_code == 403

        resumed = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume",
            headers=_auth(OPERATOR_TOKEN),
            json={"approval_id": approval_id},
        )
        assert resumed.status_code == 200, resumed.text
        assert resumed.json()["approval"]["state"] == "consumed"
        continuation_job_id = str(resumed.json()["job"]["job_id"])

        replay = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume",
            headers=_auth(OPERATOR_TOKEN),
            json={"approval_id": approval_id},
        )
        assert replay.status_code == 409
        assert "already been claimed" in replay.json()["detail"]

        continuation = _claim(client, worker_id="worker-2")
        assert continuation["job"]["job_id"] == continuation_job_id
        completion_payload = {
            "worker_id": "worker-2",
            "lease_token": continuation["lease_token"],
            "result": {"status": "validated"},
        }
        completed = client.post(
            f"/v1/worker/jobs/{continuation_job_id}/complete",
            headers=_auth(WORKER_TOKEN),
            json=completion_payload,
        )
        assert completed.status_code == 200
        repeated_completion = client.post(
            f"/v1/worker/jobs/{continuation_job_id}/complete",
            headers=_auth(WORKER_TOKEN),
            json=completion_payload,
        )
        assert repeated_completion.status_code == 200
        assert repeated_completion.json()["result"] == {"status": "validated"}

        conflicting_completion = client.post(
            f"/v1/worker/jobs/{continuation_job_id}/complete",
            headers=_auth(WORKER_TOKEN),
            json={
                **completion_payload,
                "result": {"status": "retargeted-after-commit"},
            },
        )
        assert conflicting_completion.status_code == 409
        assert "result differs" in conflicting_completion.json()["detail"]

        run = client.get(f"/v1/runs/{run_id}", headers=_auth(OPERATOR_TOKEN))
        assert run.json()["state"] == "completed"
        events = client.get(f"/v1/runs/{run_id}/events", headers=_auth(APPROVER_TOKEN)).json()
        assert [item["sequence"] for item in events] == list(range(1, len(events) + 1))
        assert "approval.approved" in {item["event_type"] for item in events}
        assert "checkpoint.claimed" in {item["event_type"] for item in events}
        assert [item["event_type"] for item in events].count("job.completed") == 1
        assert [item["event_type"] for item in events].count("run.completed") == 1


def test_submission_idempotency_requires_exact_canonical_request_and_actor(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "submission-idempotency-authority.db"))
    request = SubmitRunRequest(
        campaign_name="idempotency-authority",
        input={"nested": {"z": 3, "a": 1}, "items": [1, 2]},
        idempotency_key="submission-authority-key",
        max_attempts=3,
        job_kind=JobKind.CAMPAIGN,
    )
    with TestClient(app):
        service = app.state.control_plane
        created = service.submit_run(request, actor="alice-operator")
        exact = service.submit_run(
            request.model_copy(update={"input": {"items": [1, 2], "nested": {"a": 1, "z": 3}}}),
            actor="alice-operator",
        )
        assert exact.created is False
        assert exact.run.run_id == created.run.run_id

        conflicting_requests = (
            request.model_copy(update={"campaign_name": "different-campaign"}),
            request.model_copy(update={"input": {"nested": {"a": 1, "z": 4}}}),
            request.model_copy(update={"job_kind": JobKind.TOOL_LOOP}),
            request.model_copy(update={"max_attempts": 4}),
        )
        for conflicting in conflicting_requests:
            with pytest.raises(StateConflict, match="idempotency key"):
                service.submit_run(conflicting, actor="alice-operator")

        with pytest.raises(StateConflict, match="idempotency key"):
            service.submit_run(request, actor="different-operator")


def test_concurrent_submission_has_one_exact_durable_authority(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "concurrent-submission-authority.db"))
    exact_request = SubmitRunRequest(
        campaign_name="concurrent-idempotency",
        input={"objective": "same durable authority"},
        idempotency_key="concurrent-exact-key",
        max_attempts=3,
    )
    with TestClient(app):
        service = app.state.control_plane
        barrier = Barrier(2)

        def submit_exact() -> Any:
            barrier.wait(timeout=5)
            return service.submit_run(exact_request, actor="alice-operator")

        with ThreadPoolExecutor(max_workers=2) as pool:
            exact_results = list(pool.map(lambda _ordinal: submit_exact(), range(2)))

        assert sorted(result.created for result in exact_results) == [False, True]
        assert len({result.run.run_id for result in exact_results}) == 1
        assert len({result.job.job_id for result in exact_results}) == 1

        conflict_barrier = Barrier(2)
        conflicting_requests = (
            exact_request.model_copy(
                update={
                    "idempotency_key": "concurrent-conflict-key",
                    "input": {"winner": "a"},
                }
            ),
            exact_request.model_copy(
                update={
                    "idempotency_key": "concurrent-conflict-key",
                    "input": {"winner": "b"},
                }
            ),
        )

        def submit_conflicting(request: SubmitRunRequest) -> Any:
            conflict_barrier.wait(timeout=5)
            try:
                return service.submit_run(request, actor="alice-operator")
            except StateConflict as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as pool:
            conflict_results = list(pool.map(submit_conflicting, conflicting_requests))

        assert sum(not isinstance(result, StateConflict) for result in conflict_results) == 1
        assert sum(isinstance(result, StateConflict) for result in conflict_results) == 1

        with app.state.repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(RunRecord)) == 2
            assert session.scalar(select(func.count()).select_from(JobRecord)) == 2
            assert session.scalar(select(func.count()).select_from(EventRecord)) == 2


def test_file_sqlite_independent_services_claim_one_generic_job_once(tmp_path: Path) -> None:
    database_path = tmp_path / "independent-generic-claim.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    repository_a = ControlPlaneRepository(database_url)
    repository_a.initialize()
    repository_b = ControlPlaneRepository(database_url)
    repository_b.initialize()
    signer = CheckpointSigner(
        active_key_id="test-v1",
        keys={"test-v1": b"test-checkpoint-signing-key-32-bytes-minimum"},
    )
    service_a = ControlPlaneService(repository_a, signer)
    service_b = ControlPlaneService(repository_b, signer)
    try:
        submitted = service_a.submit_run(
            SubmitRunRequest(
                campaign_name="sqlite-claim-race",
                input={"race": "one durable winner"},
                idempotency_key="sqlite-independent-claim-race",
            ),
            actor="alice-operator",
        )
        barrier = Barrier(2)

        def claim(service: Any, worker_id: str) -> Any:
            barrier.wait(timeout=5)
            try:
                return service.claim_job(
                    ClaimJobRequest(worker_id=worker_id, lease_seconds=30),
                    actor="shared-worker-principal",
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (
                pool.submit(claim, service_a, "sqlite-worker-a"),
                pool.submit(claim, service_b, "sqlite-worker-b"),
            )
            outcomes = [future.result(timeout=15) for future in futures]

        assert not [outcome for outcome in outcomes if isinstance(outcome, Exception)]
        winners = [outcome for outcome in outcomes if outcome is not None]
        assert len(winners) == 1
        winner = winners[0]
        assert winner.job.job_id == submitted.job.job_id
        assert winner.job.attempts == 1
        assert winner.job.state is JobState.LEASED
        assert sum(outcome is None for outcome in outcomes) == 1

        with repository_a.transaction() as session:
            job = session.get(JobRecord, submitted.job.job_id)
            run = session.get(RunRecord, submitted.run.run_id)
            assert job is not None and run is not None
            assert job.state == JobState.LEASED.value
            assert job.attempts == 1
            assert job.lease_owner in {"sqlite-worker-a", "sqlite-worker-b"}
            assert run.state == RunState.RUNNING.value
    finally:
        repository_b.close()
        repository_a.close()


def test_file_sqlite_independent_services_converge_on_duplicate_completion(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "independent-duplicate-complete.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    repository_a = ControlPlaneRepository(database_url)
    repository_a.initialize()
    repository_b = ControlPlaneRepository(database_url)
    repository_b.initialize()
    signer = CheckpointSigner(
        active_key_id="test-v1",
        keys={"test-v1": b"test-checkpoint-signing-key-32-bytes-minimum"},
    )
    service_a = ControlPlaneService(repository_a, signer)
    service_b = ControlPlaneService(repository_b, signer)
    try:
        submitted = service_a.submit_run(
            SubmitRunRequest(
                campaign_name="sqlite-complete-race",
                idempotency_key="sqlite-independent-complete-race",
            ),
            actor="alice-operator",
        )
        claimed = service_a.claim_job(
            ClaimJobRequest(worker_id="sqlite-completion-worker", lease_seconds=30),
            actor="shared-worker-principal",
        )
        assert claimed is not None
        request = CompleteJobRequest(
            worker_id="sqlite-completion-worker",
            lease_token=claimed.lease_token,
            result={"attempt": 1, "completed": True},
        )
        barrier = Barrier(2)

        def complete(service: Any) -> Any:
            barrier.wait(timeout=5)
            try:
                return service.complete_job(
                    submitted.job.job_id,
                    request.model_copy(deep=True),
                    actor="shared-worker-principal",
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (pool.submit(complete, service_a), pool.submit(complete, service_b))
            outcomes = [future.result(timeout=15) for future in futures]

        assert not [outcome for outcome in outcomes if isinstance(outcome, Exception)]
        assert all(outcome.state is JobState.SUCCEEDED for outcome in outcomes)
        assert all(outcome.result == {"attempt": 1, "completed": True} for outcome in outcomes)

        exact_retry = service_a.complete_job(
            submitted.job.job_id,
            request.model_copy(deep=True),
            actor="shared-worker-principal",
        )
        assert exact_retry.result == {"attempt": 1, "completed": True}
        with pytest.raises(StateConflict, match="result differs"):
            service_b.complete_job(
                submitted.job.job_id,
                request.model_copy(
                    update={"result": {"attempt": 1.0, "completed": True}},
                    deep=True,
                ),
                actor="shared-worker-principal",
            )

        with repository_a.transaction() as session:
            job = session.get(JobRecord, submitted.job.job_id)
            run = session.get(RunRecord, submitted.run.run_id)
            assert job is not None and run is not None
            assert job.state == JobState.SUCCEEDED.value
            assert job.attempts == 1
            assert job.result == {"attempt": 1, "completed": True}
            assert run.state == RunState.COMPLETED.value
            terminal_events = session.scalar(
                select(func.count())
                .select_from(EventRecord)
                .where(
                    EventRecord.run_id == submitted.run.run_id,
                    EventRecord.event_type.in_(["job.completed", "run.completed"]),
                )
            )
            assert terminal_events == 2
    finally:
        repository_b.close()
        repository_a.close()


def test_file_sqlite_snapshot_reader_is_not_serialized_behind_reserved_writer(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "independent-reader-during-writer.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    repository_a = ControlPlaneRepository(database_url)
    repository_a.initialize()
    repository_b = ControlPlaneRepository(database_url)
    repository_b.initialize()
    signer = CheckpointSigner(
        active_key_id="test-v1",
        keys={"test-v1": b"test-checkpoint-signing-key-32-bytes-minimum"},
    )
    service_a = ControlPlaneService(repository_a, signer)
    service_b = ControlPlaneService(repository_b, signer)
    try:
        submitted = service_a.submit_run(
            SubmitRunRequest(
                campaign_name="sqlite-reader-availability",
                idempotency_key="sqlite-independent-reader-availability",
            ),
            actor="alice-operator",
        )
        writer_reserved = Event()
        release_writer = Event()

        def hold_writer_reservation() -> None:
            with repository_a.transaction() as session:
                assert session.get(RunRecord, submitted.run.run_id) is not None
                writer_reserved.set()
                assert release_writer.wait(timeout=5)

        with ThreadPoolExecutor(max_workers=2) as pool:
            writer = pool.submit(hold_writer_reservation)
            assert writer_reserved.wait(timeout=5)
            reader = pool.submit(service_b.get_run, submitted.run.run_id)
            try:
                observed = reader.result(timeout=1)
            finally:
                release_writer.set()
            writer.result(timeout=5)

        assert observed.run_id == submitted.run.run_id
        assert observed.state is RunState.QUEUED
        with (
            pytest.raises(RuntimeError, match="read transaction cannot persist"),
            repository_a.read_transaction() as session,
        ):
            record = session.get(RunRecord, submitted.run.run_id)
            assert record is not None
            record.campaign_name = "must-not-persist"
        assert service_a.get_run(submitted.run.run_id).campaign_name == (
            "sqlite-reader-availability"
        )
    finally:
        repository_b.close()
        repository_a.close()


def test_file_sqlite_read_scope_keeps_one_wal_snapshot(tmp_path: Path) -> None:
    database_path = tmp_path / "read-scope-wal-snapshot.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    bootstrap = ControlPlaneRepository(database_url)
    bootstrap.initialize()
    bootstrap.close()
    direct = sqlite3.connect(database_path)
    try:
        assert direct.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    finally:
        direct.close()

    repository_a = ControlPlaneRepository(database_url)
    repository_b = ControlPlaneRepository(database_url)
    signer = CheckpointSigner(
        active_key_id="test-v1",
        keys={"test-v1": b"test-checkpoint-signing-key-32-bytes-minimum"},
    )
    service_a = ControlPlaneService(repository_a, signer)
    service_b = ControlPlaneService(repository_b, signer)
    try:
        service_a.submit_run(
            SubmitRunRequest(
                campaign_name="sqlite-snapshot-first",
                idempotency_key="sqlite-snapshot-first",
            ),
            actor="alice-operator",
        )
        with repository_a.read_transaction() as session:
            first_count = session.scalar(select(func.count()).select_from(RunRecord))
            service_b.submit_run(
                SubmitRunRequest(
                    campaign_name="sqlite-snapshot-second",
                    idempotency_key="sqlite-snapshot-second",
                ),
                actor="alice-operator",
            )
            same_snapshot_count = session.scalar(select(func.count()).select_from(RunRecord))

        assert first_count == 1
        assert same_snapshot_count == 1
        with repository_a.read_transaction() as session:
            assert session.scalar(select(func.count()).select_from(RunRecord)) == 2
    finally:
        repository_b.close()
        repository_a.close()


def test_mutation_payloads_are_owned_snapshots_without_digest_or_signature_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(_settings(tmp_path / "owned-json-snapshots.db"))
    with TestClient(app) as client:
        service = app.state.control_plane

        submission_request = SubmitRunRequest(
            campaign_name="owned-submission",
            input={"nested": {"value": "before"}},
            idempotency_key="owned-submission-key",
        )
        original_event = service._event
        submission_mutated = False

        def mutate_submission_during_event(*args: object, **kwargs: object) -> EventRecord:
            nonlocal submission_mutated
            if not submission_mutated:
                submission_mutated = True
                submission_request.input["nested"]["value"] = "after"
            return original_event(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(service, "_event", mutate_submission_during_event)
        submitted = service.submit_run(submission_request, actor="alice-operator")
        monkeypatch.setattr(service, "_event", original_event)

        with app.state.repository.transaction() as session:
            run = session.scalar(select(RunRecord).where(RunRecord.run_id == submitted.run.run_id))
            job = session.scalar(select(JobRecord).where(JobRecord.job_id == submitted.job.job_id))
            assert run is not None and job is not None
            assert run.input == {"nested": {"value": "before"}}
            assert job.payload == {"input": {"nested": {"value": "before"}}}
            assert run.submission_authority_digest == submission_authority_digest(
                actor="alice-operator",
                campaign_name="owned-submission",
                input_value={"nested": {"value": "before"}},
                idempotency_key="owned-submission-key",
                job_kind="campaign",
                max_attempts=3,
            )

        exact = service.submit_run(
            SubmitRunRequest(
                campaign_name="owned-submission",
                input={"nested": {"value": "before"}},
                idempotency_key="owned-submission-key",
            ),
            actor="alice-operator",
        )
        assert exact.created is False

        completion_job_id = submitted.job.job_id
        completion_claim = _claim(client, worker_id="owned-completion-worker")
        completion_request = CompleteJobRequest(
            worker_id="owned-completion-worker",
            lease_token=str(completion_claim["lease_token"]),
            result={"nested": {"value": "before"}},
        )
        completion_mutated = False

        def mutate_completion_during_event(*args: object, **kwargs: object) -> EventRecord:
            nonlocal completion_mutated
            if not completion_mutated:
                completion_mutated = True
                completion_request.result["nested"]["value"] = "after"
            return original_event(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(service, "_event", mutate_completion_during_event)
        service.complete_job(
            completion_job_id,
            completion_request,
            actor="worker-service",
        )
        monkeypatch.setattr(service, "_event", original_event)
        with app.state.repository.transaction() as session:
            completed_job = session.scalar(
                select(JobRecord).where(JobRecord.job_id == completion_job_id)
            )
            assert completed_job is not None
            assert completed_job.result == {"nested": {"value": "before"}}

        _run_id, checkpoint_job_id = _submit(client, "owned-checkpoint")
        checkpoint_claim = _claim(client, worker_id="owned-checkpoint-worker")
        checkpoint_request = CreateCheckpointRequest(
            worker_id="owned-checkpoint-worker",
            lease_token=str(checkpoint_claim["lease_token"]),
            state={"nested": {"value": "before"}},
            pending_intent=ApprovalIntent(
                call_fingerprint="c" * 64,
                tool_id="owned-checkpoint-tool",
                target="https://target.invalid/owned",
                risk_tier=ToolRiskTier.T3,
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            ),
        )
        original_sign = service.signer.sign

        def mutate_checkpoint_after_signing(*args: object, **kwargs: object) -> object:
            signed = original_sign(*args, **kwargs)  # type: ignore[arg-type]
            checkpoint_request.state["nested"]["value"] = "after"
            return signed

        monkeypatch.setattr(service.signer, "sign", mutate_checkpoint_after_signing)
        created = service.create_checkpoint(
            checkpoint_job_id,
            checkpoint_request,
            actor="worker-service",
        )
        monkeypatch.setattr(service.signer, "sign", original_sign)
        with app.state.repository.transaction() as session:
            checkpoint = session.scalar(
                select(CheckpointRecord).where(
                    CheckpointRecord.checkpoint_id == created.checkpoint.checkpoint_id
                )
            )
            assert checkpoint is not None
            assert checkpoint.payload["state"] == {"nested": {"value": "before"}}
            service._verify_checkpoint(checkpoint)


def test_generic_completion_lease_is_bound_to_authenticated_worker_subject(
    tmp_path: Path,
) -> None:
    base = _settings(tmp_path / "generic-worker-subject-binding.db")
    app = create_app(
        replace(
            base,
            credentials={
                **base.credentials,
                OTHER_WORKER_TOKEN: Principal(
                    subject="other-worker-service",
                    roles=frozenset({PrincipalRole.WORKER}),
                ),
            },
        )
    )
    with TestClient(app) as client:
        _run_id, job_id = _submit(client, "worker-subject-binding")
        claimed = _claim(client, worker_id="shared-daemon-instance")
        completion = {
            "worker_id": "shared-daemon-instance",
            "lease_token": claimed["lease_token"],
            "result": {"validated": True},
        }

        wrong_principal = client.post(
            f"/v1/worker/jobs/{job_id}/complete",
            headers=_auth(OTHER_WORKER_TOKEN),
            json=completion,
        )
        assert wrong_principal.status_code == 409
        assert wrong_principal.json()["code"] == "lease_lost"

        completed = client.post(
            f"/v1/worker/jobs/{job_id}/complete",
            headers=_auth(WORKER_TOKEN),
            json=completion,
        )
        assert completed.status_code == 200, completed.text

        _second_run_id, second_job_id = _submit(client, "shared-worker-second-daemon")
        second_claim = _claim(client, worker_id="another-shared-daemon-instance")
        second_completion = client.post(
            f"/v1/worker/jobs/{second_job_id}/complete",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "another-shared-daemon-instance",
                "lease_token": second_claim["lease_token"],
                "result": {"validated": True},
            },
        )
        assert second_completion.status_code == 200, second_completion.text


def test_expired_lease_is_requeued_and_old_token_is_rejected(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "crash-recovery.db"))
    with TestClient(app) as client:
        _run_id, job_id = _submit(client, "crash")
        first = _claim(client)
        first_token = str(first["lease_token"])

        repository = app.state.repository
        with repository.transaction() as session:
            session.execute(
                update(JobRecord)
                .where(JobRecord.job_id == job_id)
                .values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )

        swept = client.post("/v1/maintenance/requeue-expired", headers=_auth(OPERATOR_TOKEN))
        assert swept.status_code == 200
        assert swept.json()["requeuedOrDeadLettered"] == 1

        second = _claim(client, worker_id="worker-2")
        assert second["job"]["attempts"] == 2
        assert second["lease_token"] != first_token
        stale = client.post(
            f"/v1/worker/jobs/{job_id}/heartbeat",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "worker-1",
                "lease_token": first_token,
                "lease_seconds": 30,
            },
        )
        assert stale.status_code == 409


def test_heartbeat_is_throttled_clock_safe_and_cannot_cross_absolute_horizon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": datetime(2026, 1, 1, tzinfo=UTC)}
    monkeypatch.setattr(control_plane_service_module, "utc_now", lambda: clock["now"])
    app = create_app(_settings(tmp_path / "lease-hard-horizon.db"))

    with TestClient(app) as client:
        run_id, job_id = _submit(client, "hard-horizon")
        claimed = _claim(client, worker_id="horizon-worker")
        lease_token = str(claimed["lease_token"])
        hard_deadline = clock["now"] + timedelta(hours=24)

        with app.state.repository.transaction() as session:
            job = session.scalar(select(JobRecord).where(JobRecord.job_id == job_id))
            assert job is not None and job.lease_deadline_at is not None
            persisted_deadline = job.lease_deadline_at
            if persisted_deadline.tzinfo is None:
                persisted_deadline = persisted_deadline.replace(tzinfo=UTC)
            assert persisted_deadline == hard_deadline

        def heartbeat() -> Any:
            return client.post(
                f"/v1/worker/jobs/{job_id}/heartbeat",
                headers=_auth(WORKER_TOKEN),
                json={
                    "worker_id": "horizon-worker",
                    "lease_token": lease_token,
                    "lease_seconds": 300,
                },
            )

        clock["now"] += timedelta(seconds=1)
        assert heartbeat().status_code == 200
        clock["now"] += timedelta(seconds=1)
        assert heartbeat().status_code == 200
        clock["now"] += timedelta(seconds=MIN_JOB_HEARTBEAT_EVENT_INTERVAL_SECONDS - 1)
        assert heartbeat().status_code == 200

        with app.state.repository.transaction() as session:
            heartbeat_events = session.scalars(
                select(EventRecord).where(
                    EventRecord.run_id == run_id,
                    EventRecord.event_type == "job.heartbeat",
                )
            ).all()
            assert len(heartbeat_events) == 2

        # A backward clock observation cannot move heartbeat authority backward
        # or manufacture another durable event.
        clock["now"] -= timedelta(seconds=30)
        rollback_heartbeat = heartbeat()
        assert rollback_heartbeat.status_code == 200
        with app.state.repository.transaction() as session:
            heartbeat_events = session.scalars(
                select(EventRecord).where(
                    EventRecord.run_id == run_id,
                    EventRecord.event_type == "job.heartbeat",
                )
            ).all()
            assert len(heartbeat_events) == 2

        # Recreate a legitimate near-horizon rolling lease and prove that the
        # next extension is capped, then reclaimed exactly at the hard fence.
        near_deadline = hard_deadline - timedelta(seconds=20)
        with app.state.repository.transaction() as session:
            session.execute(
                update(JobRecord)
                .where(JobRecord.job_id == job_id)
                .values(
                    heartbeat_at=near_deadline,
                    heartbeat_event_at=near_deadline,
                    lease_expires_at=hard_deadline - timedelta(seconds=10),
                )
            )
        clock["now"] = near_deadline
        capped = heartbeat()
        assert capped.status_code == 200
        assert datetime.fromisoformat(capped.json()["lease_expires_at"]) == hard_deadline

        clock["now"] = hard_deadline
        rejected = heartbeat()
        assert rejected.status_code == 409
        swept = client.post(
            "/v1/maintenance/requeue-expired",
            headers=_auth(OPERATOR_TOKEN),
        )
        assert swept.status_code == 200
        assert swept.json()["requeuedOrDeadLettered"] == 1
        with app.state.repository.transaction() as session:
            job = session.scalar(select(JobRecord).where(JobRecord.job_id == job_id))
            assert job is not None
            assert job.state == "queued"
            assert job.lease_deadline_at is None
            assert job.heartbeat_event_at is None


def test_tampered_checkpoint_and_event_mutation_are_blocked(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "integrity.db"))
    with TestClient(app) as client:
        run_id, job_id = _submit(client, "tamper")
        claimed = _claim(client)
        created = _checkpoint(client, job_id, str(claimed["lease_token"]), fingerprint="b" * 64)
        checkpoint_id = str(created["checkpoint"]["checkpoint_id"])
        approval_id = str(created["approval"]["approval_id"])
        approved = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=_auth(APPROVER_TOKEN),
            json={"approve": True, "reason": "approved before tampering"},
        )
        assert approved.status_code == 200

        repository = app.state.repository
        with repository.transaction() as session:
            checkpoint = session.scalar(
                select(CheckpointRecord).where(CheckpointRecord.checkpoint_id == checkpoint_id)
            )
            assert checkpoint is not None
            checkpoint.payload = {
                **checkpoint.payload,
                "state": {"turn": 999, "tampered": True},
            }

        resume = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume",
            headers=_auth(OPERATOR_TOKEN),
            json={"approval_id": approval_id},
        )
        assert resume.status_code == 409
        assert "integrity" in resume.json()["detail"]

        with (
            pytest.raises(DatabaseError, match="append-only"),
            repository.transaction() as session,
        ):
            event = session.scalar(select(EventRecord).where(EventRecord.run_id == run_id).limit(1))
            assert event is not None
            event.event_type = "event.tampered"


def test_lease_token_is_stored_only_as_a_digest(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "lease-secret.db"))
    with TestClient(app) as client:
        _run_id, job_id = _submit(client, "lease-secret")
        claimed = _claim(client)
        raw_token = str(claimed["lease_token"])
        with app.state.repository.transaction() as session:
            job = session.scalar(select(JobRecord).where(JobRecord.job_id == job_id))
            assert job is not None
            assert job.lease_token_hash is not None
            assert job.lease_token_hash != raw_token
            assert raw_token not in repr(job.payload)


def test_worker_claim_uses_bounded_long_poll(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "long-poll.db"))
    with TestClient(app) as client:
        started = monotonic()
        response = client.post(
            "/v1/worker/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "worker-long-poll",
                "kinds": ["campaign"],
                "lease_seconds": 30,
                "wait_seconds": 1,
            },
        )
        elapsed = monotonic() - started

    assert response.status_code == 204
    assert 0.9 <= elapsed < 2


def test_replay_executor_profile_environment_is_explicit_and_subject_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_required_control_plane_environment(monkeypatch)
    monkeypatch.setenv("PAJIN_CP_WORKER_SUBJECT", "worker-service")
    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_TOKEN", REPLAY_WORKER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_SUBJECT", "replay-worker-service")
    monkeypatch.setenv(
        "PAJIN_CP_REPLAY_EXECUTOR_PROFILES",
        '{"replay-worker-service":["kisa-exact-v1","kisa-exact-v2"]}',
    )

    settings = ControlPlaneSettings.from_env()

    assert settings.replay_executor_profiles == {
        "replay-worker-service": frozenset({"kisa-exact-v1", "kisa-exact-v2"})
    }
    assert settings.credentials[WORKER_TOKEN].subject == "worker-service"
    assert settings.credentials[REPLAY_WORKER_TOKEN].subject == "replay-worker-service"


@pytest.mark.parametrize(
    "raw_allowlist",
    [
        "",
        "[]",
        '{"unknown-worker":["kisa-exact-v1"]}',
        '{"worker-service":[]}',
        '{"worker-service":"kisa-exact-v1"}',
        '{"worker-service":["invalid profile"]}',
        '{"worker-service":["kisa-exact-v1","kisa-exact-v1"]}',
        ('{"worker-service":["kisa-exact-v1"],"worker-service":["kisa-exact-v2"]}'),
        '{"worker-service":[NaN]}',
        '{"worker-service":' + ("[" * 6) + '"kisa-exact-v1"' + ("]" * 6) + "}",
    ],
)
def test_replay_executor_profile_environment_rejects_ambiguous_authority(
    monkeypatch: pytest.MonkeyPatch,
    raw_allowlist: str,
) -> None:
    _set_required_control_plane_environment(monkeypatch)
    monkeypatch.setenv("PAJIN_CP_WORKER_SUBJECT", "worker-service")
    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_TOKEN", REPLAY_WORKER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_SUBJECT", "replay-worker-service")
    monkeypatch.setenv("PAJIN_CP_REPLAY_EXECUTOR_PROFILES", raw_allowlist)

    with pytest.raises(RuntimeError, match="PAJIN_CP_REPLAY_EXECUTOR_PROFILES"):
        ControlPlaneSettings.from_env()


def test_replay_executor_profile_parser_rejects_oversized_authority() -> None:
    raw_allowlist = "{" + '"padding":"' + ("x" * (64 * 1024)) + '"}'

    with pytest.raises(RuntimeError, match="PAJIN_CP_REPLAY_EXECUTOR_PROFILES"):
        _parse_replay_executor_profiles(raw_allowlist, credentials={})


def test_replay_profile_environment_requires_a_distinct_dedicated_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_required_control_plane_environment(monkeypatch)
    monkeypatch.setenv(
        "PAJIN_CP_REPLAY_EXECUTOR_PROFILES",
        '{"worker-service":["kisa-exact-v1"]}',
    )

    with pytest.raises(RuntimeError, match="PAJIN_CP_REPLAY_WORKER_TOKEN"):
        ControlPlaneSettings.from_env()

    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_SUBJECT", "replay-worker-service")
    with pytest.raises(RuntimeError, match="credential must be distinct"):
        ControlPlaneSettings.from_env()

    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_TOKEN", REPLAY_WORKER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_SUBJECT", "worker-service")
    with pytest.raises(RuntimeError, match="subject must be distinct"):
        ControlPlaneSettings.from_env()


def test_programmatic_replay_executor_profiles_reject_non_worker_subject(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="authenticated Worker principal"):
        replace(
            _settings(tmp_path / "invalid-replay-profile-subject.db"),
            replay_executor_profiles={"alice-operator": frozenset({"kisa-exact-v1"})},
        )


@pytest.mark.parametrize(
    ("configuration", "expected_error"),
    [
        ("multi-role", "Worker authority cannot be combined"),
        ("duplicate-subject", "one dedicated Worker-only credential"),
    ],
)
def test_programmatic_replay_profiles_require_one_worker_only_credential(
    tmp_path: Path,
    configuration: str,
    expected_error: str,
) -> None:
    base = _settings(tmp_path / f"invalid-replay-principal-{configuration}.db")
    replay_principal = Principal(
        subject="replay-worker-service",
        roles=frozenset(
            {PrincipalRole.WORKER, PrincipalRole.OPERATOR}
            if configuration == "multi-role"
            else {PrincipalRole.WORKER}
        ),
    )
    credentials = {**base.credentials, REPLAY_WORKER_TOKEN: replay_principal}
    if configuration == "duplicate-subject":
        credentials[OTHER_WORKER_TOKEN] = Principal(
            subject="replay-worker-service",
            roles=frozenset({PrincipalRole.WORKER}),
        )

    with pytest.raises(ValueError, match=expected_error):
        replace(
            base,
            credentials=credentials,
            replay_executor_profiles={"replay-worker-service": frozenset({"kisa-exact-v1"})},
        )


@pytest.mark.parametrize(
    ("roles", "expected_error"),
    [
        (
            frozenset(
                {
                    PrincipalRole.OPERATOR,
                    PrincipalRole.APPROVER,
                    PrincipalRole.AUDITOR,
                }
            ),
            "operator and approver authority cannot be combined",
        ),
        (
            frozenset({PrincipalRole.WORKER, PrincipalRole.OPERATOR}),
            "Worker authority cannot be combined with non-Worker authority",
        ),
        (
            frozenset({PrincipalRole.WORKER, PrincipalRole.AUDITOR}),
            "Worker authority cannot be combined with non-Worker authority",
        ),
    ],
    ids=["operator-approver", "worker-operator", "worker-auditor"],
)
def test_programmatic_settings_reject_one_token_with_combined_authority(
    tmp_path: Path,
    roles: frozenset[PrincipalRole],
    expected_error: str,
) -> None:
    base = _settings(tmp_path / "combined-token-authority.db")
    credentials = {
        **base.credentials,
        "combined-authority-token-that-is-long-enough": Principal(
            subject="combined-authority",
            roles=roles,
        ),
    }

    with pytest.raises(ValueError, match=expected_error):
        replace(base, credentials=credentials)


@pytest.mark.parametrize(
    ("first_roles", "second_roles", "expected_error"),
    [
        (
            frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            "operator and approver authority cannot be combined",
        ),
        (
            frozenset({PrincipalRole.WORKER}),
            frozenset({PrincipalRole.AUDITOR}),
            "Worker authority cannot be combined with non-Worker authority",
        ),
        (
            frozenset({PrincipalRole.WORKER}),
            frozenset({PrincipalRole.OPERATOR}),
            "Worker authority cannot be combined with non-Worker authority",
        ),
    ],
    ids=["operator-approver", "worker-auditor", "worker-operator"],
)
def test_programmatic_settings_reject_cross_token_authority_for_one_subject(
    tmp_path: Path,
    first_roles: frozenset[PrincipalRole],
    second_roles: frozenset[PrincipalRole],
    expected_error: str,
) -> None:
    base = _settings(tmp_path / "cross-token-authority.db")
    credentials = {
        "shared-subject-token-one-that-is-long-enough": Principal(
            subject="shared-authority",
            roles=first_roles,
        ),
        "shared-subject-token-two-that-is-long-enough": Principal(
            subject="shared-authority",
            roles=second_roles,
        ),
    }

    with pytest.raises(ValueError, match=expected_error):
        replace(base, credentials=credentials)


def test_settings_hold_an_immutable_snapshot_of_validated_credentials(
    tmp_path: Path,
) -> None:
    base = _settings(tmp_path / "immutable-credential-authority.db")
    supplied_credentials = dict(base.credentials)
    settings = replace(base, credentials=supplied_credentials)
    injected_token = "post-validation-injected-token-that-is-long-enough"
    injected_principal = Principal(
        subject="post-validation-injected-authority",
        roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.APPROVER}),
    )

    supplied_credentials[injected_token] = injected_principal

    assert injected_token not in settings.credentials
    with pytest.raises(TypeError):
        settings.credentials[injected_token] = injected_principal  # type: ignore[index]


def test_legitimate_audited_roles_remain_configurable_and_route_isolated(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path / "legitimate-role-separation.db")
    app = create_app(settings)

    with TestClient(app) as client:
        operator_session = client.get("/v1/session", headers=_auth(OPERATOR_TOKEN))
        approver_session = client.get("/v1/session", headers=_auth(APPROVER_TOKEN))
        operator_submission = client.post(
            "/v1/runs",
            headers=_auth(OPERATOR_TOKEN),
            json={
                "campaign_name": "role-separation-control",
                "idempotency_key": "role-separation-control",
            },
        )
        approver_submission = client.post(
            "/v1/runs",
            headers=_auth(APPROVER_TOKEN),
            json={
                "campaign_name": "role-separation-denied",
                "idempotency_key": "role-separation-denied",
            },
        )
        decision_body = {"approve": True, "reason": "role boundary verification"}
        operator_decision = client.post(
            "/v1/approvals/missing-approval/decision",
            headers=_auth(OPERATOR_TOKEN),
            json=decision_body,
        )
        approver_decision = client.post(
            "/v1/approvals/missing-approval/decision",
            headers=_auth(APPROVER_TOKEN),
            json=decision_body,
        )

    assert operator_session.status_code == 200
    assert set(operator_session.json()["roles"]) == {"operator", "auditor"}
    assert approver_session.status_code == 200
    assert set(approver_session.json()["roles"]) == {"approver", "auditor"}
    assert operator_submission.status_code == 200
    assert approver_submission.status_code == 403
    assert operator_decision.status_code == 403
    assert approver_decision.status_code == 404


def test_generic_and_replay_worker_credentials_are_route_isolated(tmp_path: Path) -> None:
    base = _settings(tmp_path / "worker-route-isolation.db")
    settings = replace(
        base,
        credentials={
            **base.credentials,
            REPLAY_WORKER_TOKEN: Principal(
                subject="replay-worker-service",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        replay_executor_profiles={"replay-worker-service": frozenset({"kisa-exact-v1"})},
    )
    app = create_app(settings)
    job_id = f"job_{'4' * 32}"
    ticket_id = f"replay-ticket_{'3' * 32}"
    lease_token = "lease-token-that-is-at-least-32-characters"
    generic_requests = (
        (
            "/v1/worker/jobs/claim",
            {"worker_id": "replay-worker", "kinds": ["campaign"]},
        ),
        (
            f"/v1/worker/jobs/{job_id}/heartbeat",
            {
                "worker_id": "replay-worker",
                "lease_token": lease_token,
                "lease_seconds": 30,
            },
        ),
        (
            f"/v1/worker/jobs/{job_id}/complete",
            {"worker_id": "replay-worker", "lease_token": lease_token, "result": {}},
        ),
        (
            f"/v1/worker/jobs/{job_id}/fail",
            {
                "worker_id": "replay-worker",
                "lease_token": lease_token,
                "error": "bounded failure",
            },
        ),
        (
            f"/v1/worker/jobs/{job_id}/checkpoints",
            {
                "worker_id": "replay-worker",
                "lease_token": lease_token,
                "state": {},
                "pending_intent": {
                    "call_fingerprint": "a" * 64,
                    "tool_id": "mock.approval-probe",
                    "target": "lab://approval-check",
                    "risk_tier": 3,
                    "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                },
            },
        ),
    )
    replay_requests = (
        (
            "/v1/worker/replay/jobs/claim",
            {"executor_profile": "kisa-exact-v1", "lease_seconds": 30},
        ),
        (
            f"/v1/worker/replay/jobs/{job_id}/heartbeat",
            {
                "executor_profile": "kisa-exact-v1",
                "lease_token": lease_token,
                "lease_seconds": 30,
                "ticket_id": ticket_id,
                "fencing_value": 1,
            },
        ),
        (
            f"/v1/worker/replay/jobs/{job_id}/tool-permits",
            {
                "executor_profile": "kisa-exact-v1",
                "lease_token": lease_token,
                "ticket_id": ticket_id,
                "fencing_value": 1,
                "call_ordinal": 1,
            },
        ),
        (
            f"/v1/worker/replay/jobs/{job_id}/finalize",
            {
                "executor_profile": "kisa-exact-v1",
                "lease_token": lease_token,
                "ticket_id": ticket_id,
                "fencing_value": 1,
                "output_staging_id": f"stage_{'5' * 32}",
            },
        ),
    )

    with TestClient(app) as client:
        for path, body in generic_requests:
            response = client.post(
                path,
                headers=_auth(REPLAY_WORKER_TOKEN),
                json=body,
            )
            assert response.status_code == 403, (path, response.text)
            assert response.json() == {
                "detail": ("dedicated Replay Worker credential cannot access generic Worker routes")
            }

        for path, body in replay_requests:
            response = client.post(path, headers=_auth(WORKER_TOKEN), json=body)
            assert response.status_code == 403, (path, response.text)
            assert response.json() == {
                "detail": (
                    "authenticated Worker principal is not registered for this Replay executor"
                )
            }

        generic_claim = client.post(
            "/v1/worker/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json={"worker_id": "generic-worker", "kinds": ["campaign"]},
        )
        replay_claim = client.post(
            "/v1/worker/replay/jobs/claim",
            headers=_auth(REPLAY_WORKER_TOKEN),
            json={"executor_profile": "kisa-exact-v1", "lease_seconds": 30},
        )

    assert generic_claim.status_code == 204
    assert replay_claim.status_code == 204


def test_replay_worker_routes_are_role_protected_typed_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty_app = create_app(_settings(tmp_path / "replay-route-fail-closed.db"))
    claim_body = {"executor_profile": "kisa-exact-v1", "lease_seconds": 30}
    with TestClient(empty_app) as client:
        rejected = client.post(
            "/v1/worker/replay/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json=claim_body,
        )
    assert rejected.status_code == 403
    assert rejected.json() == {
        "detail": "authenticated Worker principal is not registered for this Replay executor"
    }

    settings = replace(
        _settings(tmp_path / "replay-routes.db"),
        replay_executor_profiles={"worker-service": frozenset({"kisa-exact-v1"})},
    )
    app = create_app(settings)
    job_id = f"job_{'4' * 32}"
    ticket_id = f"replay-ticket_{'3' * 32}"
    lease_token = "lease-token-that-is-at-least-32-characters"
    permit_body = {
        "executor_profile": "kisa-exact-v1",
        "lease_token": lease_token,
        "ticket_id": ticket_id,
        "fencing_value": 7,
        "call_ordinal": 1,
    }
    seen: dict[str, object] = {}

    with TestClient(app) as client:
        missing_auth = client.post(
            "/v1/worker/replay/jobs/claim",
            json=claim_body,
        )
        wrong_role = client.post(
            "/v1/worker/replay/jobs/claim",
            headers=_auth(OPERATOR_TOKEN),
            json=claim_body,
        )
        empty_claim = client.post(
            "/v1/worker/replay/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json=claim_body,
        )

        def issue_permit(
            selected_job_id: str,
            request: ReplayToolPermitRequest,
            *,
            actor: str,
        ) -> ReplayToolPermitView:
            seen.update(job_id=selected_job_id, request=request, actor=actor)
            return _replay_tool_permit_view()

        monkeypatch.setattr(
            app.state.control_plane,
            "issue_replay_tool_permit",
            issue_permit,
        )
        issued = client.post(
            f"/v1/worker/replay/jobs/{job_id}/tool-permits",
            headers=_auth(WORKER_TOKEN),
            json=permit_body,
        )
        injected = client.post(
            f"/v1/worker/replay/jobs/{job_id}/tool-permits",
            headers=_auth(WORKER_TOKEN),
            json={**permit_body, "target": "https://attacker.invalid"},
        )

        def reject_heartbeat(*_args: object, **_kwargs: object) -> None:
            raise LeaseRejected("Replay job lease has expired")

        monkeypatch.setattr(
            app.state.control_plane,
            "heartbeat_replay_job",
            reject_heartbeat,
        )
        heartbeat = client.post(
            f"/v1/worker/replay/jobs/{job_id}/heartbeat",
            headers=_auth(WORKER_TOKEN),
            json={
                "executor_profile": "kisa-exact-v1",
                "lease_token": lease_token,
                "lease_seconds": 30,
                "ticket_id": ticket_id,
                "fencing_value": 7,
            },
        )
        openapi = client.get("/openapi.json").json()

    assert missing_auth.status_code == 401
    assert wrong_role.status_code == 403
    assert empty_claim.status_code == 204
    assert issued.status_code == 200, issued.text
    assert seen == {
        "job_id": job_id,
        "request": ReplayToolPermitRequest.model_validate(permit_body),
        "actor": "worker-service",
    }
    assert lease_token not in issued.text
    assert issued.headers["cache-control"] == "no-store, max-age=0"
    assert issued.headers["pragma"] == "no-cache"
    assert injected.status_code == 422
    assert heartbeat.status_code == 409
    assert heartbeat.json() == {
        "detail": "Replay job lease has expired",
        "code": "lease_lost",
    }

    replay_paths = (
        "/v1/worker/replay/jobs/claim",
        "/v1/worker/replay/jobs/{job_id}/heartbeat",
        "/v1/worker/replay/jobs/{job_id}/tool-permits",
    )
    paths = openapi["paths"]
    assert all(path in paths for path in replay_paths)
    assert all("409" in paths[path]["post"]["responses"] for path in replay_paths)
    assert {path for path in paths if path.startswith("/v1/replay")} == {
        "/v1/replay-comparisons/batches/{batch_id}",
        "/v1/replay/source-artifacts",
        "/v1/replay/batches",
        "/v1/replay/batches/{batch_id}",
        "/v1/replay/batches/{batch_id}/attestation",
        "/v1/replay/batches/{batch_id}/projection",
        "/v1/replay/attestation/trust-anchor",
        "/v1/replay/items/{item_id}",
        "/v1/replay/tickets/{ticket_id}",
        "/v1/replay/tickets/{ticket_id}/finalization",
    }
