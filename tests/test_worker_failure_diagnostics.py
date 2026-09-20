"""Worker diagnostics are bounded observations, never retry or accounting authority."""

import io
import json
import ssl
import subprocess
from datetime import UTC, datetime
from http.client import HTTPMessage
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest
from test_provider import _worker_entry
from test_provider_session import StubProviderGateway, _chat, _port

from pajin.agents.base import ModelCallFailure
from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest
from pajin.runtime.error_safety import audit_safe_worker_failure
from pajin.runtime.worker import WorkerResult, WorkerStatus
from pajin.tools.gateway import GatewayOutcome

_PRIVATE = "private-path-canary-credential-MUST-NOT-APPEAR"


def _input(target: str = "https://fixture.invalid/v1/chat/completions") -> str:
    return json.dumps(
        {
            "pajinEnvelopeVersion": 1,
            "secrets": {"provider-api-key": _PRIVATE},
            "payload": {
                "providerId": "diagnostic-fixture",
                "target": target,
                "request": {
                    "model": "fixture",
                    "messages": [{"role": "user", "content": _PRIVATE}],
                },
            },
        }
    )


def _pinned_input() -> str:
    value = json.loads(_input())
    value["payload"].update(
        {
            "requestTimeoutSeconds": 180,
            "transportVersion": "pajin.web-analysis.provider-transport/v2",
        }
    )
    return json.dumps(value)


def _provider_response() -> io.BytesIO:
    return io.BytesIO(
        json.dumps(
            {
                "id": "fixture-result",
                "model": "fixture",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        ).encode()
    )


@pytest.mark.parametrize(
    "action",
    ["openai-chat-completion", "openai-chat-completion-v2"],
)
def test_legacy_provider_actions_keep_fixed_30_second_open_timeout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    action: str,
) -> None:
    worker = _worker_entry()
    observed_timeouts: list[float] = []

    def open_response(request: object, *, timeout: float) -> io.BytesIO:
        observed_timeouts.append(timeout)
        return _provider_response()

    monkeypatch.setattr(worker, "_open_http", open_response)
    monkeypatch.setattr(worker.sys, "argv", ["worker_entry.py", action])
    monkeypatch.setattr(worker.sys, "stdin", io.StringIO(_input()))

    assert worker.main() == 0
    assert observed_timeouts == [30.0]
    assert json.loads(capsys.readouterr().out)["content"] == "ok"


def test_pinned_provider_action_passes_exact_180_second_open_timeout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    worker = _worker_entry()
    observed_timeouts: list[float] = []

    def open_response(request: object, *, timeout: float) -> io.BytesIO:
        observed_timeouts.append(timeout)
        return _provider_response()

    monkeypatch.setattr(worker, "_open_http", open_response)
    monkeypatch.setattr(worker.sys, "argv", ["worker_entry.py", "openai-chat-completion-v3"])
    monkeypatch.setattr(worker.sys, "stdin", io.StringIO(_pinned_input()))

    assert worker.main() == 0
    assert observed_timeouts == [180.0]
    assert json.loads(capsys.readouterr().out)["content"] == "ok"


@pytest.mark.parametrize(
    ("drop_field", "replacement"),
    [
        ("requestTimeoutSeconds", None),
        (None, {"requestTimeoutSeconds": 179}),
        (None, {"transportVersion": "pajin.web-analysis.provider-transport/v1"}),
        (None, {"unexpected": True}),
    ],
)
def test_pinned_provider_action_rejects_unpinned_payload_before_http(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    drop_field: str | None,
    replacement: dict[str, object] | None,
) -> None:
    worker = _worker_entry()
    value = json.loads(_pinned_input())
    if drop_field is not None:
        value["payload"].pop(drop_field)
    if replacement is not None:
        value["payload"].update(replacement)
    http_calls = 0

    def fail_if_opened(*args: object, **kwargs: object) -> io.BytesIO:
        nonlocal http_calls
        http_calls += 1
        return _provider_response()

    monkeypatch.setattr(worker, "_open_http", fail_if_opened)
    monkeypatch.setattr(worker.sys, "argv", ["worker_entry.py", "openai-chat-completion-v3"])
    monkeypatch.setattr(worker.sys, "stdin", io.StringIO(json.dumps(value)))

    assert worker.main() == 65
    captured = capsys.readouterr()
    assert captured.out == ""
    assert http_calls == 0
    assert "stage=worker-action" in audit_safe_worker_failure(captured.err, exit_code=65)


@pytest.mark.parametrize(
    ("error", "category", "exit_code"),
    [
        (TimeoutError(_PRIVATE), "timeout", 70),
        (OSError(_PRIVATE), "io", 70),
        (RuntimeError(_PRIVATE), "runtime", 70),
        (subprocess.TimeoutExpired(_PRIVATE, 30, output=_PRIVATE), "subprocess-timeout", 70),
        (URLError(ssl.SSLCertVerificationError(_PRIVATE)), "tls-verification", 65),
        (URLError(_PRIVATE), "transport-unknown", 65),
        (URLError(ConnectionRefusedError(_PRIVATE)), "connection", 65),
        (
            HTTPError(_PRIVATE, 401, _PRIVATE, HTTPMessage(), io.BytesIO(_PRIVATE.encode())),
            "http-response",
            65,
        ),
    ],
)
def test_observed_provider_open_failure_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
    category: str,
    exit_code: int,
) -> None:
    worker = _worker_entry()

    def fail(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(worker, "_open_http", fail)
    monkeypatch.setattr(worker.sys, "argv", ["worker_entry.py", "openai-chat-completion"])
    monkeypatch.setattr(worker.sys, "stdin", io.StringIO(_input()))
    assert worker.main() == exit_code
    captured = capsys.readouterr()
    assert captured.out == ""
    assert _PRIVATE not in captured.err
    assert audit_safe_worker_failure(captured.err, exit_code=exit_code) == (
        f"worker-report-v1; stage=provider-open; category={category}; detail=omitted"
    )


@pytest.mark.parametrize("failure_stage", ["provider-read", "provider-normalize"])
def test_read_and_decode_are_distinct_observed_stages(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure_stage: str,
) -> None:
    worker = _worker_entry()

    class Response(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            if failure_stage == "provider-read":
                raise TimeoutError(_PRIVATE)
            return super().read(size)

    monkeypatch.setattr(worker, "_open_http", lambda *a, **k: Response(_PRIVATE.encode()))
    monkeypatch.setattr(worker.sys, "argv", ["worker_entry.py", "openai-chat-completion"])
    monkeypatch.setattr(worker.sys, "stdin", io.StringIO(_input()))
    expected_exit = 70 if failure_stage == "provider-read" else 65
    assert worker.main() == expected_exit
    captured = capsys.readouterr()
    diagnostic = audit_safe_worker_failure(captured.err, exit_code=expected_exit)
    assert f"stage={failure_stage}" in diagnostic
    assert (
        "category=timeout" in diagnostic
        if expected_exit == 70
        else "category=invalid-data" in diagnostic
    )
    assert _PRIVATE not in captured.err
    # A subsequent request cannot inherit the previous failure stage.
    monkeypatch.setattr(worker.sys, "stdin", io.StringIO("[]"))
    assert worker.main() == 65
    assert "stage=worker-input" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("stderr", "exit_code", "truncated"),
    [
        ("worker action failed\n", 70, False),
        (_PRIVATE, 70, False),
        (
            "worker action failed\npajin-worker-failure-v1 stage=provider-open category=timeout\n"
            + _PRIVATE,
            70,
            False,
        ),
        (
            "worker action failed\npajin-worker-failure-v1 stage=provider-open category=timeout\n",
            0,
            False,
        ),
        (
            "worker action failed\npajin-worker-failure-v1 stage=provider-open category=timeout\n",
            70,
            True,
        ),
        (
            "worker action failed\npajin-worker-failure-v1 stage="
            + _PRIVATE
            + " category=timeout\n",
            70,
            False,
        ),
        (
            "worker action failed\npajin-worker-failure-v1 stage=provider-open category="
            + _PRIVATE
            + "\n",
            70,
            False,
        ),
    ],
)
def test_unrecognized_legacy_injected_or_truncated_report_remains_unknown(
    stderr: str,
    exit_code: int,
    truncated: bool,
) -> None:
    assert audit_safe_worker_failure(stderr, exit_code=exit_code, truncated=truncated) == (
        "worker-report-v1; stage=unknown; category=unknown; detail=omitted"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("executed", [True, False])
async def test_provider_preserves_diagnostics_evidence_and_charge_without_retry(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    executed: bool,
) -> None:
    class DiagnosticGateway(StubProviderGateway):
        async def execute(
            self,
            campaign: CampaignManifest,
            grant: CapabilityGrant,
            request: ToolRequest,
            *,
            used_calls: int,
        ) -> GatewayOutcome:
            outcome = await super().execute(campaign, grant, request, used_calls=used_calls)
            now = datetime.now(UTC)
            return outcome.model_copy(
                update={
                    "worker_result": WorkerResult(
                        execution_id="diagnostic-execution",
                        backend="test",
                        status=WorkerStatus.FAILED,
                        exit_code=70,
                        started_at=now,
                        finished_at=now,
                        stderr="worker action failed\n"
                        "pajin-worker-failure-v1 stage=provider-open category=timeout\n",
                    )
                }
            )

    gateway = DiagnosticGateway(executed=executed, success=False, bound_sources=True)
    port, budget = _port(tmp_path, sample_campaign, gateway)
    with pytest.raises(ModelCallFailure) as failure:
        await port.chat(role="test", attempt=1, chat=_chat())
    assert gateway.calls == 1
    events = [json.loads(line) for line in port._store.events_path.read_text().splitlines()]
    assert [e["event_type"] for e in events] == ["model.call.started", "model.call.failed"]
    assert f"evidence/{gateway.requests[0].request_id}.json" in json.dumps(events)
    if executed:
        assert "stage=provider-open; category=timeout" in str(failure.value)
        assert "stage=provider-open; category=timeout" in json.dumps(events)
        assert budget.snapshot()["modelCalls"] == 1
        assert budget.snapshot()["costUsd"] > 0
        assert budget.snapshot()["modelTokens"] > 10
    else:
        assert "did not execute" in str(failure.value)
        assert "category=timeout" not in json.dumps(events)
        assert budget.snapshot()["modelCalls"] == 0
        assert budget.snapshot()["costUsd"] == 0


@pytest.mark.parametrize("mode", ["success", "denied", "malformed", "timeout"])
def test_worker_diagnostic_through_actual_authenticated_http(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
) -> None:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread
    from time import sleep

    worker = _worker_entry()
    authorized: list[bool] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_POST(self) -> None:
            authorized.append(self.headers.get("Authorization") == f"Bearer {_PRIVATE}")
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(401 if mode == "denied" else 200)
            self.end_headers()
            if mode == "timeout":
                sleep(0.2)
                return
            body = (
                _PRIVATE.encode()
                if mode in {"denied", "malformed"}
                else json.dumps(
                    {
                        "id": "fixture-result",
                        "model": "fixture",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": "ok"},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    }
                ).encode()
            )
            self.wfile.write(body)

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.handle_request)
        server.timeout = 2
        thread.start()
        real_open = worker._open_http
        if mode == "timeout":
            monkeypatch.setattr(
                worker, "_open_http", lambda req, **kw: real_open(req, timeout=0.05)
            )
        monkeypatch.setattr(worker.sys, "argv", ["worker_entry.py", "openai-chat-completion"])
        monkeypatch.setattr(
            worker.sys,
            "stdin",
            io.StringIO(_input(f"http://127.0.0.1:{server.server_port}/v1/chat/completions")),
        )
        try:
            code = worker.main()
        finally:
            thread.join(timeout=3)
        assert not thread.is_alive()
    captured = capsys.readouterr()
    assert authorized == [True]
    assert _PRIVATE not in captured.err
    if mode == "success":
        assert code == 0 and captured.err == ""
        assert json.loads(captured.out)["content"] == "ok"
    else:
        assert code == (70 if mode == "timeout" else 65)
        assert captured.out == ""
        expected = {
            "denied": "provider-open; category=http-response",
            "malformed": "provider-normalize; category=invalid-data",
            "timeout": "provider-read; category=timeout",
        }[mode]
        assert expected in audit_safe_worker_failure(captured.err, exit_code=code)
