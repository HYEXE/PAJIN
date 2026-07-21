import json
from base64 import b64encode
from datetime import UTC, datetime
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.domain.models import ToolRequest, ToolRiskTier
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.base import (
    EGRESS_HTTP_RECEIPT_VERSION,
    ToolRegistry,
    audit_http_target,
    decode_bounded_json_response,
    host_observed_http_receipts,
    http_target_sha256,
)
from pajin.tools.http import HTTPGetTool

TARGET = "https://example.invalid/api/report"


def _body_fields(body: bytes) -> dict[str, str]:
    return {
        "bodyPreview": body.decode("utf-8", errors="replace"),
        "bodySha256": sha256(body).hexdigest(),
        "responseBodyBase64": b64encode(body).decode("ascii"),
    }


def _request(*, method: str = "GET", target: str = TARGET) -> ToolRequest:
    return ToolRequest(
        request_id="tool_http_contract",
        agent_id="agent:test",
        tool_id="http.get",
        target=target,
        method=method,
    )


def _result(
    output: object,
    *,
    stdout_truncated: bool = False,
) -> WorkerResult:
    now = datetime.now(UTC)
    return WorkerResult(
        execution_id="exec_http_contract",
        backend="contract-test",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout=json.dumps(output),
        stdout_truncated=stdout_truncated,
        started_at=now,
        finished_at=now,
    )


def _adversarial_json_payload(shape: str) -> bytes:
    if shape == "duplicate":
        return b'{"value":1,"value":2}'
    if shape == "nonfinite":
        return b'{"value":NaN}'
    if shape == "depth":
        return b'{"value":' + (b"[" * 20_000) + b"null" + (b"]" * 20_000) + b"}"
    if shape == "nodes":
        return b'{"values":[' + (b"0," * 20_000) + b"0]}"
    raise AssertionError(f"unsupported test shape: {shape}")


def test_bounded_json_response_preserves_normal_payload_and_canonical_digest() -> None:
    body = b'{ "nested": {"ok": true}, "items": [1, 2] }'

    raw, decoded, digest = decode_bounded_json_response(
        b64encode(body).decode("ascii"),
        max_bytes=len(body),
    )

    assert raw == body
    assert decoded == {"nested": {"ok": True}, "items": [1, 2]}
    assert digest == sha256(b'{"items":[1,2],"nested":{"ok":true}}').hexdigest()


@pytest.mark.parametrize(
    "shape",
    ["duplicate", "nonfinite", "depth", "nodes"],
)
def test_bounded_json_response_rejects_ambiguous_or_resource_bomb_payloads(
    shape: str,
) -> None:
    body = _adversarial_json_payload(shape)

    with pytest.raises(ValueError, match="strict JSON object"):
        decode_bounded_json_response(
            b64encode(body).decode("ascii"),
            max_bytes=len(body),
        )


@pytest.mark.parametrize(
    "shape",
    ["duplicate", "nonfinite", "depth", "nodes"],
)
def test_proxy_log_rejects_ambiguous_or_resource_bomb_events(shape: str) -> None:
    event = _adversarial_json_payload(shape).decode("ascii")
    worker_result = _result({}).model_copy(
        update={
            "backend": "docker",
            "network_log": f'{{"event":"ready","port":8080}}\n{event}',
        }
    )

    with pytest.raises(ValueError, match="malformed JSON"):
        host_observed_http_receipts(worker_result, network_log_trusted=True)


def test_http_get_accepts_only_get_requests() -> None:
    tool = HTTPGetTool()

    with pytest.raises(ValueError, match="requires GET"):
        tool.prepare(_request(method="POST"))

    job = tool.prepare(_request())
    assert job.command == ["http-get"]
    assert json.loads(job.stdin) == {"target": TARGET}


def test_http_get_accepts_strict_output_bound_to_the_exact_target() -> None:
    outcome = HTTPGetTool().interpret(
        _request(),
        _result(
            {
                "target": TARGET,
                "status": 200,
                "contentType": "application/json",
                **_body_fields(b"{}"),
            }
        ),
    )

    assert outcome.success
    assert outcome.error is None
    assert outcome.data["target"] == TARGET
    assert outcome.data["status"] == 200


@pytest.mark.parametrize(
    "output",
    [
        {"target": "https://other.invalid/api/report", "status": 200},
        {"target": TARGET, "status": "200"},
        {"target": TARGET, "status": True},
        {"status": 200},
        {"target": TARGET, "status": 200, "unexpected": "field"},
    ],
)
def test_http_get_rejects_unbound_or_malformed_worker_output(output: object) -> None:
    outcome = HTTPGetTool().interpret(_request(), _result(output))

    assert not outcome.success
    assert outcome.error is not None
    assert "invalid worker output" in outcome.error


def test_http_get_rejects_truncated_worker_output() -> None:
    outcome = HTTPGetTool().interpret(
        _request(),
        _result({"target": TARGET, "status": 200}, stdout_truncated=True),
    )

    assert not outcome.success
    assert outcome.error is not None
    assert "truncated" in outcome.error


def test_http_get_treats_terminal_redirect_as_failure() -> None:
    outcome = HTTPGetTool().interpret(
        _request(),
        _result(
            {
                "target": TARGET,
                "status": 302,
                "contentType": "text/plain",
                **_body_fields(b"redirecting"),
                "error": "redirect response was not followed",
            }
        ),
    )

    assert not outcome.success
    assert outcome.error == "redirect response was not followed"


def test_http_get_success_requires_body_bound_host_receipt() -> None:
    target = "http://example.invalid/api/report"
    request = _request(target=target)
    worker_result = _result(
        {
            "target": target,
            "status": 200,
            "contentType": "application/json",
            **_body_fields(b"{}"),
        }
    ).model_copy(
        update={
            "backend": "docker",
            "network_log": "\n".join(
                [
                    json.dumps({"event": "ready", "port": 8080}),
                    json.dumps(
                        {
                            "event": "allow",
                            "receiptVersion": EGRESS_HTTP_RECEIPT_VERSION,
                            "sequence": 1,
                            "method": "GET",
                            "target": audit_http_target(target),
                            "targetSha256": http_target_sha256(target),
                            "address": "203.0.113.10",
                            "status": 200,
                            "responseBodySha256": sha256(b"{}").hexdigest(),
                            "responseJsonSha256": sha256(b"{}").hexdigest(),
                        }
                    ),
                ]
            ),
        }
    )
    tool = HTTPGetTool()
    result = tool.interpret(request, worker_result)

    tool.validate_trusted_execution(
        request,
        result,
        worker_result,
        network_log_trusted=True,
    )

    with pytest.raises(ValueError, match="host-observed"):
        tool.validate_trusted_execution(
            request,
            result,
            worker_result,
            network_log_trusted=False,
        )


def test_host_observed_receipts_are_immutable_snapshots() -> None:
    target = "http://example.invalid/api/report"
    worker_result = _result({}).model_copy(
        update={
            "backend": "docker",
            "network_log": "\n".join(
                [
                    json.dumps({"event": "ready", "port": 8080}),
                    json.dumps(
                        {
                            "event": "allow",
                            "receiptVersion": EGRESS_HTTP_RECEIPT_VERSION,
                            "sequence": 1,
                            "method": "GET",
                            "target": audit_http_target(target),
                            "targetSha256": http_target_sha256(target),
                            "address": "203.0.113.10",
                            "status": 200,
                            "responseBodySha256": sha256(b"{}").hexdigest(),
                            "responseJsonSha256": sha256(b"{}").hexdigest(),
                        }
                    ),
                ]
            ),
        }
    )

    receipts = host_observed_http_receipts(worker_result, network_log_trusted=True)

    assert receipts is not None
    with pytest.raises(ValidationError, match="frozen"):
        receipts[0].status = 500


def test_host_observed_receipts_reject_non_utf8_log_text() -> None:
    worker_result = _result({}).model_copy(update={"backend": "docker", "network_log": "\ud800"})

    with pytest.raises(ValueError, match="UTF-8"):
        host_observed_http_receipts(worker_result, network_log_trusted=True)


def test_tool_registry_seals_the_registered_spec() -> None:
    tool = HTTPGetTool()
    registry = ToolRegistry()
    registry.register(tool)
    registered_spec = registry.spec("http.get")

    with pytest.raises(AttributeError):
        registered_spec.categories.add("late-category")
    object.__setattr__(registered_spec, "tool_id", "http.replaced")
    tool.spec = registered_spec.model_copy(update={"risk_tier": ToolRiskTier.T0})

    assert registry.spec("http.get").tool_id == "http.get"
    with pytest.raises(RuntimeError, match="changed after registration"):
        registry.tool("http.get")
