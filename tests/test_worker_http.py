import errno
import importlib.util
import json
import os
import subprocess
import sys
import time
from base64 import b64encode
from datetime import UTC, datetime, timedelta
from email.message import Message
from hashlib import sha256
from io import BytesIO, StringIO
from pathlib import Path
from types import ModuleType, SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

TARGET = "https://example.invalid/api/report"


def _worker_entry() -> ModuleType:
    path = Path(__file__).parents[1] / "containers" / "worker" / "worker_entry.py"
    spec = importlib.util.spec_from_file_location("pajin_http_worker_entry", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stub_linux_isolation_host(
    worker: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(worker.os, "geteuid", lambda: 10001, raising=False)
    monkeypatch.setattr(worker.os, "ST_RDONLY", 1, raising=False)
    monkeypatch.setattr(
        worker.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_flag=1),
        raising=False,
    )


def test_http_worker_installs_a_redirect_refusing_handler() -> None:
    worker = _worker_entry()
    handler = worker._NoRedirectHandler()

    assert any(
        isinstance(installed, worker._NoRedirectHandler)
        for installed in worker._HTTP_OPENER.handlers
    )

    redirected = handler.redirect_request(
        Request(TARGET),
        None,
        302,
        "Found",
        Message(),
        "https://other.invalid/redirected",
    )

    assert redirected is None


def test_http_worker_installs_verified_https_peer_observation() -> None:
    worker = _worker_entry()

    assert any(
        isinstance(installed, worker._ObservingHTTPSHandler)
        for installed in worker._HTTP_OPENER.handlers
    )

    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ai.example.test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    expected_spki = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    assert worker._tls_leaf_spki_sha256(
        certificate.public_bytes(serialization.Encoding.DER)
    ) == sha256(expected_spki).hexdigest()


def test_ai_worker_exports_verified_https_peer_leaf_spki(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()
    peer_leaf_spki_sha256 = "c" * 64
    tls_session_binding_sha256 = "d" * 64

    class HTTPSResponse:
        status = 200
        pajin_tls_peer_leaf_spki_sha256 = peer_leaf_spki_sha256
        pajin_tls_session_binding_sha256 = tls_session_binding_sha256

        def __enter__(self) -> object:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                {
                    "sessionId": "pajin:test:https-worker",
                    "message": {"role": "assistant", "content": "ok"},
                }
            ).encode()

    class HTTPSOpener:
        def open(self, _request: Request, timeout: int) -> HTTPSResponse:
            assert timeout == 10
            return HTTPSResponse()

    monkeypatch.setattr(worker, "_HTTP_OPENER", HTTPSOpener())

    response, latency, observed_spki, observed_session_binding = worker._post_ai_turn(
        "https://ai.example.test/v1/chat",
        {
            "sessionId": "pajin:test:https-worker",
            "messages": [{"role": "user", "content": "hello"}],
        },
    )

    assert response["message"]["content"] == "ok"
    assert latency >= 0
    assert observed_spki == peer_leaf_spki_sha256
    assert observed_session_binding == tls_session_binding_sha256


def test_ai_worker_hashes_only_tls12_unique_channel_binding() -> None:
    worker = _worker_entry()

    class TLS12Socket:
        def version(self) -> str:
            return "TLSv1.2"

        def get_channel_binding(self, binding_type: str) -> bytes:
            assert binding_type == "tls-unique"
            return b"worker-and-target-finished"

    class TLS13Socket:
        def version(self) -> str:
            return "TLSv1.3"

        def get_channel_binding(self, _binding_type: str) -> bytes:
            raise AssertionError("TLS 1.3 must not use RFC 5929 tls-unique")

    assert worker._tls_unique_binding_sha256(TLS12Socket()) == sha256(
        worker._TLS_UNIQUE_BINDING_DOMAIN + b"worker-and-target-finished"
    ).hexdigest()
    assert worker._tls_unique_binding_sha256(TLS13Socket()) is None


def test_ai_worker_rejects_https_response_without_peer_leaf_spki(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()

    class HTTPSResponse:
        status = 200

        def __enter__(self) -> object:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _limit: int) -> bytes:
            return b'{"message":{"role":"assistant","content":"ok"}}'

    class HTTPSOpener:
        def open(self, _request: Request, timeout: int) -> HTTPSResponse:
            assert timeout == 10
            return HTTPSResponse()

    monkeypatch.setattr(worker, "_HTTP_OPENER", HTTPSOpener())

    with pytest.raises(ValueError, match="omitted its verified peer leaf SPKI"):
        worker._post_ai_turn(
            "https://ai.example.test/v1/chat",
            {"messages": [{"role": "user", "content": "hello"}]},
        )


@pytest.mark.parametrize(
    "target",
    [
        "file:///etc/passwd",
        "data:text/plain,secret",
        "ftp://example.invalid/resource",
        "http:///missing-authority",
        "https://user:password@example.invalid/resource",
        "https://example.invalid/resource#ignored-fragment",
        "https://example.invalid:99999/resource",
    ],
)
def test_http_worker_rejects_non_http_or_ambiguous_urls_before_open(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    worker = _worker_entry()

    class UnexpectedOpener:
        def open(self, _request: Request, _timeout: int) -> None:
            raise AssertionError("unsafe URL reached urllib opener")

    monkeypatch.setattr(worker, "_HTTP_OPENER", UnexpectedOpener())

    with pytest.raises(ValueError, match="Worker HTTP request"):
        worker._open_http(Request(target), timeout=10)


def test_http_worker_returns_redirect_as_a_terminal_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()

    class RedirectingOpener:
        request: Request | None = None

        def open(self, request: Request, timeout: int) -> None:
            assert timeout == 10
            self.request = request
            raise HTTPError(
                request.full_url,
                302,
                "Found",
                Message(),
                BytesIO(b"redirecting"),
            )

    opener = RedirectingOpener()
    monkeypatch.setattr(worker, "_HTTP_OPENER", opener)

    output = worker.http_get({"target": TARGET})

    assert opener.request is not None
    assert opener.request.get_method() == "GET"
    assert output == {
        "target": TARGET,
        "status": 302,
        "contentType": None,
        "bodyPreview": "redirecting",
        "bodySha256": sha256(b"redirecting").hexdigest(),
        "responseBodyBase64": b64encode(b"redirecting").decode("ascii"),
        "error": "redirect response was not followed",
    }


def test_all_specialized_http_actions_refuse_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()
    requests: list[tuple[str, int, str]] = []

    class RedirectingOpener:
        def open(self, request: Request, timeout: int) -> None:
            requests.append((request.full_url, timeout, request.get_method()))
            raise HTTPError(
                request.full_url,
                302,
                "Found",
                Message(),
                BytesIO(b"redirecting"),
            )

    monkeypatch.setattr(worker, "_HTTP_OPENER", RedirectingOpener())

    with pytest.raises(ValueError, match="redirect"):
        worker._get_bug_bounty_observation(
            "http://host.docker.internal:8770/v1/users/lookup",
            "1",
            "baseline",
        )
    with pytest.raises(ValueError, match="redirect"):
        worker.ctf_web_backup_probe(
            {
                "target": "http://host.docker.internal:8780/backup/config.json.bak",
                "challengeId": "web-backup-lab",
                "scenarioId": "web.exposed-backup-config",
            }
        )
    with pytest.raises(ValueError, match="HTTP 302"):
        worker._post_ai_turn(
            "http://host.docker.internal:8765/v1/chat",
            {"messages": []},
        )
    with pytest.raises(ValueError, match="HTTP 302"):
        worker.openai_chat_completion(
            {
                "providerId": "test-provider",
                "target": "http://host.docker.internal:8790/v1/chat/completions",
                "request": {
                    "model": "fixed-model",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": False,
                },
            },
            {"provider-api-key": "secret-token"},
        )

    assert [timeout for _target, timeout, _method in requests] == [10, 10, 10, 30]
    assert [method for _target, _timeout, method in requests] == ["GET", "GET", "POST", "POST"]


def test_isolation_check_accepts_inert_non_loopback_interfaces_without_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()
    _stub_linux_isolation_host(worker, monkeypatch)

    def blocked_connection(*_args: object, **_kwargs: object) -> None:
        raise OSError("blocked")

    monkeypatch.setattr(worker.socket, "create_connection", blocked_connection)
    monkeypatch.setattr(worker.socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0")])
    monkeypatch.setattr(worker, "_network_route_interfaces", lambda: ["lo"])

    output = worker.isolation_check()

    assert output["externalNetworkProbeBlocked"] is True
    assert output["onlyLoopbackInterfaces"] is False
    assert output["onlyLoopbackNetwork"] is True
    assert output["networkInterfaces"] == ["eth0", "lo"]
    assert output["networkRouteInterfaces"] == ["lo"]
    assert output["networkBlocked"] is True


def test_isolation_check_rejects_a_non_loopback_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()
    _stub_linux_isolation_host(worker, monkeypatch)

    def blocked_connection(*_args: object, **_kwargs: object) -> None:
        raise OSError("blocked")

    monkeypatch.setattr(worker.socket, "create_connection", blocked_connection)
    monkeypatch.setattr(worker.socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0")])
    monkeypatch.setattr(worker, "_network_route_interfaces", lambda: ["eth0", "lo"])

    output = worker.isolation_check()

    assert output["externalNetworkProbeBlocked"] is True
    assert output["onlyLoopbackNetwork"] is False
    assert output["networkBlocked"] is False


def test_isolation_check_fails_closed_when_interfaces_cannot_be_enumerated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()
    _stub_linux_isolation_host(worker, monkeypatch)

    def blocked_connection(*_args: object, **_kwargs: object) -> None:
        raise OSError("blocked")

    def unreadable_interfaces() -> list[tuple[int, str]]:
        raise OSError("unreadable")

    monkeypatch.setattr(worker.socket, "create_connection", blocked_connection)
    monkeypatch.setattr(worker.socket, "if_nameindex", unreadable_interfaces)
    monkeypatch.setattr(worker, "_network_route_interfaces", lambda: ["lo"])

    output = worker.isolation_check()

    assert output["externalNetworkProbeBlocked"] is True
    assert output["networkInterfaces"] is None
    assert output["onlyLoopbackNetwork"] is False
    assert output["networkBlocked"] is False


def test_isolation_check_accepts_only_loopback_with_blocked_external_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()
    _stub_linux_isolation_host(worker, monkeypatch)

    def blocked_connection(*_args: object, **_kwargs: object) -> None:
        raise OSError("blocked")

    monkeypatch.setattr(worker.socket, "create_connection", blocked_connection)
    monkeypatch.setattr(worker.socket, "if_nameindex", lambda: [(1, "lo")])
    monkeypatch.setattr(worker, "_network_route_interfaces", lambda: ["lo"])

    output = worker.isolation_check()

    assert output["networkInterfaces"] == ["lo"]
    assert output["networkRouteInterfaces"] == ["lo"]
    assert output["onlyLoopbackInterfaces"] is True
    assert output["onlyLoopbackNetwork"] is True
    assert output["externalNetworkProbeBlocked"] is True
    assert output["networkBlocked"] is True


def test_direct_network_check_requires_a_definitive_kernel_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()

    def unreachable(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.ENETUNREACH, "network is unreachable")

    monkeypatch.setattr(worker.socket, "create_connection", unreachable)

    output = worker.direct_network_check({})

    assert output == {
        "directNetworkBlocked": True,
        "probe": "1.1.1.1:443",
        "failureKind": "network-unreachable",
    }


@pytest.mark.parametrize(
    "error",
    [
        OSError(errno.ECONNREFUSED, "connection refused"),
        TimeoutError("timed out"),
        OSError("ambiguous failure"),
    ],
)
def test_direct_network_check_does_not_treat_ambiguous_failure_as_isolation(
    monkeypatch: pytest.MonkeyPatch,
    error: OSError,
) -> None:
    worker = _worker_entry()

    def ambiguous(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(worker.socket, "create_connection", ambiguous)

    output = worker.direct_network_check({})

    assert output["directNetworkBlocked"] is False
    assert output["failureKind"] == "inconclusive"


def test_direct_network_check_rejects_caller_selected_endpoint() -> None:
    with pytest.raises(ValueError, match="agent-selected"):
        _worker_entry().direct_network_check({"host": "internal.example", "port": 443})


def test_worker_wire_input_is_bounded_strict_json(monkeypatch: pytest.MonkeyPatch) -> None:
    worker = _worker_entry()

    with pytest.raises(ValueError, match="strict bounded JSON"):
        worker._read_worker_input(StringIO('{"target":"first","target":"forged"}'))
    with pytest.raises(ValueError, match="strict bounded JSON"):
        worker._read_worker_input(StringIO('{"value":NaN}'))

    monkeypatch.setattr(worker, "MAX_WORKER_INPUT_BYTES", 16)
    oversized = StringIO('{"value":"' + "x" * 100 + '"}')
    with pytest.raises(ValueError, match="byte limit"):
        worker._read_worker_input(oversized)
    assert oversized.tell() <= worker._WORKER_INPUT_CHUNK_CHARS


def test_worker_secret_envelope_rejects_downgrade_and_extra_fields() -> None:
    worker = _worker_entry()

    with pytest.raises(ValueError, match="version"):
        worker._unwrap_worker_envelope({"pajinEnvelopeVersion": 2, "payload": {}})
    with pytest.raises(ValueError, match="unexpected fields"):
        worker._unwrap_worker_envelope(
            {
                "pajinEnvelopeVersion": 1,
                "payload": {},
                "secrets": {"provider-api-key": "secret"},
                "ignored": True,
            }
        )


def test_mcp_child_drains_both_streams_while_retaining_only_bounded_prefixes() -> None:
    worker = _worker_entry()
    completed = worker._run_bounded_child(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "sys.stdout.buffer.write(b'o' * 1000000); sys.stdout.buffer.flush(); "
                "sys.stderr.buffer.write(b'e' * 1000000); sys.stderr.buffer.flush()"
            ),
        ],
        input_bytes=b"",
        timeout_seconds=5,
        stdout_limit=64,
        stderr_limit=96,
    )

    assert completed.returncode == 0
    assert completed.stdout == b"o" * 64
    assert completed.stderr == b"e" * 96
    assert completed.stdout_truncated
    assert completed.stderr_truncated


@pytest.mark.parametrize(
    ("stream", "message"),
    [
        ("stdout", "output exceeded byte limit"),
        ("stderr", "stderr exceeded byte limit"),
    ],
)
def test_mcp_call_fails_closed_on_truncated_child_stream(
    monkeypatch: pytest.MonkeyPatch,
    stream: str,
    message: str,
) -> None:
    worker = _worker_entry()
    completed = worker._BoundedChildResult(
        returncode=0,
        stdout=b'{"isError":false,"structuredContent":null,"content":[]}',
        stderr=b"",
        stdout_truncated=stream == "stdout",
        stderr_truncated=stream == "stderr",
    )
    monkeypatch.setattr(worker, "_run_bounded_child", lambda *_args, **_kwargs: completed)

    with pytest.raises(ValueError, match=message):
        worker.mcp_call(
            {
                "serverId": "demo-security",
                "toolName": "inspect_text",
                "arguments": {},
            }
        )


@pytest.mark.skipif(os.name != "posix", reason="MCP process-group cleanup is POSIX-only")
def test_mcp_child_timeout_cleans_up_descendants(
    tmp_path: Path,
) -> None:
    worker = _worker_entry()
    orphan_marker = tmp_path / "orphan-was-left-running"
    grandchild = (
        "import pathlib,time; time.sleep(0.5); "
        f"pathlib.Path({str(orphan_marker)!r}).write_text('orphan')"
    )
    parent = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
        "time.sleep(10)"
    )

    with pytest.raises(subprocess.TimeoutExpired):
        worker._run_bounded_child(
            [sys.executable, "-c", parent],
            input_bytes=b"",
            timeout_seconds=0.1,
            stdout_limit=64,
            stderr_limit=64,
        )

    # The descendant would create this marker if process-group cleanup failed.
    time.sleep(0.7)
    assert not orphan_marker.exists()


def test_mcp_child_base_exception_still_runs_process_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()

    class InterruptingProcess:
        def __init__(self) -> None:
            self.stdin = BytesIO()
            self.stdout = BytesIO()
            self.stderr = BytesIO()
            self.pid = 12345
            self.cleanup_waited = False

        def wait(self, timeout: float | None = None) -> int:
            if timeout == 1:
                raise KeyboardInterrupt
            assert timeout == worker._MCP_PROCESS_REAP_SECONDS
            self.cleanup_waited = True
            return -9

        def poll(self) -> None:
            return None

        def kill(self) -> None:
            return None

    process = InterruptingProcess()
    killed: list[object] = []
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(worker, "_kill_child_process_group", killed.append)

    with pytest.raises(KeyboardInterrupt):
        worker._run_bounded_child(
            ["ignored"],
            input_bytes=b"payload",
            timeout_seconds=1,
            stdout_limit=64,
            stderr_limit=64,
        )

    assert killed == [process]
    assert process.cleanup_waited


def test_mcp_child_reap_treats_process_lookup_race_as_already_exited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()

    class ExitedDuringKillProcess:
        def __init__(self) -> None:
            self.pid = 12345
            self.wait_calls = 0

        def wait(self, timeout: float | None = None) -> int:
            assert timeout == worker._MCP_PROCESS_REAP_SECONDS
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise subprocess.TimeoutExpired("ignored", timeout)
            return -9

        def kill(self) -> None:
            raise ProcessLookupError

    process = ExitedDuringKillProcess()
    killed: list[object] = []
    monkeypatch.setattr(worker, "_kill_child_process_group", killed.append)

    worker._terminate_and_reap_mcp_child(process)

    assert killed == [process]
    assert process.wait_calls == 2


def test_mcp_child_thread_start_failure_cleans_process_and_unowned_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()

    class StartFailingThread:
        created = 0

        def __init__(self, **kwargs: object) -> None:
            import threading

            type(self).created += 1
            self.index = type(self).created
            self.thread = threading.Thread(**kwargs)

        def start(self) -> None:
            if self.index == 2:
                raise RuntimeError("thread start failed")
            self.thread.start()

        def join(self, timeout: float | None = None) -> None:
            self.thread.join(timeout=timeout)

        def is_alive(self) -> bool:
            return self.thread.is_alive()

    class StartFailureProcess:
        def __init__(self) -> None:
            self.stdin = BytesIO()
            self.stdout = BytesIO()
            self.stderr = BytesIO()
            self.pid = 12345
            self.cleanup_waited = False

        def wait(self, timeout: float | None = None) -> int:
            assert timeout == worker._MCP_PROCESS_REAP_SECONDS
            self.cleanup_waited = True
            return -9

        def poll(self) -> None:
            return None

        def kill(self) -> None:
            return None

    process = StartFailureProcess()
    killed: list[object] = []
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(worker, "Thread", StartFailingThread)
    monkeypatch.setattr(worker, "_kill_child_process_group", killed.append)

    with pytest.raises(RuntimeError, match="thread start failed"):
        worker._run_bounded_child(
            ["ignored"],
            input_bytes=b"payload",
            timeout_seconds=1,
            stdout_limit=64,
            stderr_limit=64,
        )

    assert killed == [process]
    assert process.cleanup_waited
    assert process.stdin.closed
    assert process.stdout.closed
    assert process.stderr.closed


def test_mcp_child_thread_constructor_failure_cleans_process_and_all_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()

    class ConstructionFailingThread:
        def __init__(self, **_kwargs: object) -> None:
            raise RuntimeError("thread construction failed")

    class ConstructionFailureProcess:
        def __init__(self) -> None:
            self.stdin = BytesIO()
            self.stdout = BytesIO()
            self.stderr = BytesIO()
            self.pid = 12345
            self.cleanup_waited = False

        def wait(self, timeout: float | None = None) -> int:
            assert timeout == worker._MCP_PROCESS_REAP_SECONDS
            self.cleanup_waited = True
            return -9

        def poll(self) -> None:
            return None

        def kill(self) -> None:
            return None

    process = ConstructionFailureProcess()
    killed: list[object] = []
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(worker, "Thread", ConstructionFailingThread)
    monkeypatch.setattr(worker, "_kill_child_process_group", killed.append)

    with pytest.raises(RuntimeError, match="thread construction failed"):
        worker._run_bounded_child(
            ["ignored"],
            input_bytes=b"payload",
            timeout_seconds=1,
            stdout_limit=64,
            stderr_limit=64,
        )

    assert killed == [process]
    assert process.cleanup_waited
    assert process.stdin.closed
    assert process.stdout.closed
    assert process.stderr.closed


def test_mcp_child_ordinary_cleanup_error_preserves_primary_and_closes_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker_entry()

    class ConstructionFailingThread:
        def __init__(self, **_kwargs: object) -> None:
            raise RuntimeError("thread construction failed")

    class ConstructionFailureProcess:
        def __init__(self) -> None:
            self.stdin = BytesIO()
            self.stdout = BytesIO()
            self.stderr = BytesIO()

    process = ConstructionFailureProcess()
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(worker, "Thread", ConstructionFailingThread)

    def fail_reap(_process: object) -> None:
        raise RuntimeError("cleanup failed")

    monkeypatch.setattr(worker, "_terminate_and_reap_mcp_child", fail_reap)

    with pytest.raises(RuntimeError, match="thread construction failed") as captured:
        worker._run_bounded_child(
            ["ignored"],
            input_bytes=b"payload",
            timeout_seconds=1,
            stdout_limit=64,
            stderr_limit=64,
        )

    assert captured.value.__notes__ == ["MCP child cleanup was incomplete"]
    assert process.stdin.closed
    assert process.stdout.closed
    assert process.stderr.closed


@pytest.mark.parametrize("interrupt_type", [KeyboardInterrupt, SystemExit])
def test_mcp_child_cleanup_interrupt_takes_precedence_after_closing_pipes(
    monkeypatch: pytest.MonkeyPatch,
    interrupt_type: type[BaseException],
) -> None:
    worker = _worker_entry()

    class ConstructionFailingThread:
        def __init__(self, **_kwargs: object) -> None:
            raise RuntimeError("thread construction failed")

    class ConstructionFailureProcess:
        def __init__(self) -> None:
            self.stdin = BytesIO()
            self.stdout = BytesIO()
            self.stderr = BytesIO()

    process = ConstructionFailureProcess()
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(worker, "Thread", ConstructionFailingThread)

    def interrupt_reap(_process: object) -> None:
        raise interrupt_type

    monkeypatch.setattr(worker, "_terminate_and_reap_mcp_child", interrupt_reap)

    with pytest.raises(interrupt_type) as captured:
        worker._run_bounded_child(
            ["ignored"],
            input_bytes=b"payload",
            timeout_seconds=1,
            stdout_limit=64,
            stderr_limit=64,
        )

    assert isinstance(captured.value.__cause__, RuntimeError)
    assert str(captured.value.__cause__) == "thread construction failed"
    assert process.stdin.closed
    assert process.stdout.closed
    assert process.stderr.closed
