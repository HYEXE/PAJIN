import asyncio
import base64
import importlib.util
import json
from hashlib import sha256
from pathlib import Path
from types import ModuleType

import pytest

from pajin.tools.base import audit_http_target


@pytest.fixture
def proxy_module(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    policy = {
        "allow": ["https://example.com/**"],
        "deny": [],
        "allowed_methods": ["GET"],
        "allow_private_networks": False,
        "max_exchange_seconds": 30.0,
    }
    encoded = base64.b64encode(json.dumps(policy).encode()).decode()
    monkeypatch.setenv("PAJIN_EGRESS_POLICY_B64", encoded)
    path = Path("containers/egress-proxy/proxy.py")
    spec = importlib.util.spec_from_file_location("pajin_test_egress_proxy", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_https_connect_requires_host_wide_allow_rule(proxy_module: ModuleType) -> None:
    proxy_module.POLICY = {
        "allow": ["https://example.com/api/**"],
        "deny": [],
        "allowed_methods": ["GET"],
    }

    assert not proxy_module.request_allowed("CONNECT", "https://example.com/", authority_only=True)


def test_https_connect_rejects_query_constrained_host_wide_rule(
    proxy_module: ModuleType,
) -> None:
    proxy_module.POLICY = {
        "allow": ["https://example.com/**?tenant=approved"],
        "deny": [],
        "allowed_methods": ["GET"],
    }

    assert not proxy_module.request_allowed("CONNECT", "https://example.com/", authority_only=True)


def test_https_connect_fails_closed_for_any_authority_deny(proxy_module: ModuleType) -> None:
    proxy_module.POLICY = {
        "allow": ["https://example.com/**"],
        "deny": ["https://example.com/admin/**"],
        "allowed_methods": ["GET"],
    }

    assert not proxy_module.request_allowed("CONNECT", "https://example.com/", authority_only=True)


def test_proxy_audit_target_redacts_query_values(proxy_module: ModuleType) -> None:
    redacted = proxy_module.audit_target("https://example.com/api?token=secret&account=alice")

    assert redacted == "https://example.com/api?<redacted>"
    assert "secret" not in redacted
    assert "alice" not in redacted


def test_proxy_and_host_share_canonical_audit_target(proxy_module: ModuleType) -> None:
    target = "http://EXAMPLE.com.:80/%61pi?role=%61dmin"

    assert proxy_module.audit_target(target) == audit_http_target(target)
    assert proxy_module.audit_target(target) == "http://example.com/api?<redacted>"


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com:0/path",
        "http://example.com:65536/path",
        "http://example.com:not-a-port/path",
        "http://example.com/path#fragment",
        "http://example.com/safe/../admin",
        "http://example.com/safe/..;matrix/admin",
        "http://example.com/%2e%2e/admin",
        "http://example.com/%252e%252e/admin",
        "http://example.com/safe%2fadmin",
        "http://example.com/safe%255cadmin",
        "http://example.com/safe\\admin",
        "http://example.com/safe%0aadmin",
        "http://example.com/safe%zzadmin",
        "http://example.com/%2561dmin",
        "http://%65xample.com/path",
        "http://example.com../path",
        "http://example.com/path?role=%2561dmin",
        "http://example.com/path?value=unsafe\x7f",
    ],
)
def test_proxy_rejects_ambiguous_or_unenforceable_urls(
    proxy_module: ModuleType,
    target: str,
) -> None:
    with pytest.raises(ValueError):
        proxy_module.parse_url(target)


def test_proxy_allows_benign_percent_encoded_path(proxy_module: ModuleType) -> None:
    parsed = proxy_module.parse_url("http://example.com/reports/hello%20world/%25")

    assert parsed.path == "/reports/hello%20world/%25"


def test_proxy_canonicalizes_path_and_hostname_before_scope_comparison(
    proxy_module: ModuleType,
) -> None:
    proxy_module.POLICY = {
        "allow": ["http://*.example/**"],
        "deny": ["http://xn--bcher-kva.example/admin/**"],
        "allowed_methods": ["GET"],
    }

    assert not proxy_module.request_allowed(
        "GET",
        "http://b\N{LATIN SMALL LETTER U WITH DIAERESIS}cher.example/%61dmin/export",
        authority_only=False,
    )
    assert proxy_module.parse_url("http://example.com./%61pi").path == "/api"
    assert (
        proxy_module.parse_url(
            "http://b\N{LATIN SMALL LETTER U WITH DIAERESIS}cher.example/api"
        ).hostname
        == "xn--bcher-kva.example"
    )


def test_proxy_canonicalizes_query_unreserved_characters_before_scope_comparison(
    proxy_module: ModuleType,
) -> None:
    proxy_module.POLICY = {
        "allow": ["http://example.com/**"],
        "deny": ["http://example.com/api?role=admin"],
        "allowed_methods": ["GET"],
    }

    assert not proxy_module.request_allowed(
        "GET",
        "http://example.com/api?role=%61dmin",
        authority_only=False,
    )


@pytest.mark.parametrize(
    "headers",
    [
        [("Content-Length", "1"), ("Content-Length", "1")],
        [("Content-Length", "1"), ("content-length", "2")],
        [("Transfer-Encoding", "chunked")],
    ],
)
def test_proxy_rejects_ambiguous_request_body_framing(
    proxy_module: ModuleType,
    headers: list[tuple[str, str]],
) -> None:
    with pytest.raises(ValueError):
        proxy_module.content_length(headers)


def test_proxy_enforces_reserved_request_count(proxy_module: ModuleType) -> None:
    proxy_module.POLICY["max_requests"] = 2
    proxy_module.REQUEST_COUNT = 0

    assert proxy_module.reserve_request() == 1
    assert proxy_module.reserve_request() == 2
    with pytest.raises(PermissionError, match="request count"):
        proxy_module.reserve_request()


class _MemoryWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.closed = False
        self.wait_closed_calls = 0

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.wait_closed_calls += 1

    def is_closing(self) -> bool:
        return self.closed


def _canonical_digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def test_non_json_response_receipt_still_binds_raw_body(proxy_module: ModuleType) -> None:
    body = b"plain text response"
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )

    assert proxy_module.response_json_receipt(response) == (
        200,
        sha256(body).hexdigest(),
        None,
    )


def test_plaintext_http_post_emits_body_bound_json_receipt(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request_value = {"messages": [{"role": "user", "content": "hello"}], "turn": 0}
    response_value = {"message": {"role": "assistant", "content": "hello"}}
    request_body = json.dumps(request_value, separators=(",", ":")).encode()
    response_body = json.dumps(response_value, separators=(",", ":")).encode()
    upstream_response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(response_body)).encode()
        + b"\r\n\r\n"
        + response_body
    )
    client_writer = _MemoryWriter()
    upstream_writer = _MemoryWriter()

    async def resolve_target(_host: str, port: int) -> tuple[str, int]:
        return "203.0.113.10", port

    monkeypatch.setattr(proxy_module, "resolve_target", resolve_target)
    proxy_module.POLICY = {
        "allow": ["http://example.com/v1/chat*"],
        "deny": [],
        "allowed_methods": ["POST"],
        "max_exchange_seconds": 30.0,
        "max_requests": 1,
    }

    async def exercise_proxy() -> None:
        request_reader = asyncio.StreamReader()
        request_reader.feed_data(request_body)
        request_reader.feed_eof()
        upstream_reader = asyncio.StreamReader()
        upstream_reader.feed_data(upstream_response)
        upstream_reader.feed_eof()

        async def open_connection(_address: str, _port: int):
            return upstream_reader, upstream_writer

        monkeypatch.setattr(proxy_module.asyncio, "open_connection", open_connection)
        await proxy_module.handle_http(
            "POST",
            "http://example.com/v1/chat?token=secret",
            "HTTP/1.1",
            [("Content-Type", "application/json"), ("Content-Length", str(len(request_body)))],
            request_reader,
            client_writer,
            sequence=1,
        )

    asyncio.run(exercise_proxy())

    assert bytes(client_writer.data) == upstream_response
    assert client_writer.closed
    assert upstream_writer.closed
    assert upstream_writer.wait_closed_calls == 1
    assert request_body in upstream_writer.data
    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert events == [
        {
            "event": "allow",
            "receiptVersion": proxy_module.RECEIPT_VERSION,
            "sequence": 1,
            "method": "POST",
            "target": "http://example.com/v1/chat?<redacted>",
            "targetSha256": sha256(b"http://example.com/v1/chat?token=secret").hexdigest(),
            "address": "203.0.113.10",
            "status": 200,
            "responseBodySha256": sha256(response_body).hexdigest(),
            "requestJsonSha256": _canonical_digest(request_value),
            "responseJsonSha256": _canonical_digest(response_value),
        }
    ]


def test_plaintext_json_get_emits_query_redacted_body_bound_receipt(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = "http://example.com/v1/users?id=1%27+OR+%271%27%3D%271"
    response_value = {"recordCount": 2, "synthetic": True}
    response_body = json.dumps(response_value, separators=(",", ":")).encode()
    upstream_response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(response_body)).encode()
        + b"\r\n\r\n"
        + response_body
    )
    client_writer = _MemoryWriter()
    upstream_writer = _MemoryWriter()

    async def resolve_target(_host: str, port: int) -> tuple[str, int]:
        return "203.0.113.10", port

    monkeypatch.setattr(proxy_module, "resolve_target", resolve_target)
    proxy_module.POLICY = {
        "allow": ["http://example.com/v1/users*"],
        "deny": [],
        "allowed_methods": ["GET"],
        "max_exchange_seconds": 30.0,
        "max_requests": 1,
    }

    async def exercise_proxy() -> None:
        request_reader = asyncio.StreamReader()
        request_reader.feed_eof()
        upstream_reader = asyncio.StreamReader()
        upstream_reader.feed_data(upstream_response)
        upstream_reader.feed_eof()

        async def open_connection(_address: str, _port: int):
            return upstream_reader, upstream_writer

        monkeypatch.setattr(proxy_module.asyncio, "open_connection", open_connection)
        await proxy_module.handle_http(
            "GET",
            target,
            "HTTP/1.1",
            [],
            request_reader,
            client_writer,
            sequence=1,
        )

    asyncio.run(exercise_proxy())

    events_text = capsys.readouterr().err
    assert "1%27" not in events_text
    events = [json.loads(line) for line in events_text.splitlines()]
    assert events == [
        {
            "event": "allow",
            "receiptVersion": proxy_module.RECEIPT_VERSION,
            "sequence": 1,
            "method": "GET",
            "target": "http://example.com/v1/users?<redacted>",
            "targetSha256": sha256(target.encode()).hexdigest(),
            "address": "203.0.113.10",
            "status": 200,
            "responseBodySha256": sha256(response_body).hexdigest(),
            "responseJsonSha256": _canonical_digest(response_value),
        }
    ]


def test_plaintext_receipt_is_flushed_before_worker_receives_response(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response_body = b'{"ok":true}'
    upstream_response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(response_body)).encode()
        + b"\r\n\r\n"
        + response_body
    )
    order: list[str] = []

    class OrderedClientWriter(_MemoryWriter):
        def write(self, data: bytes) -> None:
            order.append("worker-response")
            super().write(data)

    client_writer = OrderedClientWriter()
    upstream_writer = _MemoryWriter()

    async def resolve_target(_host: str, port: int) -> tuple[str, int]:
        return "203.0.113.10", port

    async def open_connection(_address: str, _port: int):
        upstream_reader = asyncio.StreamReader()
        upstream_reader.feed_data(upstream_response)
        upstream_reader.feed_eof()
        return upstream_reader, upstream_writer

    def log_event(event: str, **fields: object) -> None:
        del event, fields
        order.append("receipt")

    monkeypatch.setattr(proxy_module, "resolve_target", resolve_target)
    monkeypatch.setattr(proxy_module.asyncio, "open_connection", open_connection)
    monkeypatch.setattr(proxy_module, "log_event", log_event)
    proxy_module.POLICY = {
        "allow": ["http://example.com/v1/status"],
        "deny": [],
        "allowed_methods": ["GET"],
        "max_exchange_seconds": 30.0,
        "max_requests": 1,
    }

    async def exercise_proxy() -> None:
        request_reader = asyncio.StreamReader()
        request_reader.feed_eof()
        await proxy_module.handle_http(
            "GET",
            "http://example.com/v1/status",
            "HTTP/1.1",
            [],
            request_reader,
            client_writer,
            sequence=1,
        )

    asyncio.run(exercise_proxy())

    assert order == ["receipt", "worker-response"]


def test_plaintext_http_closes_upstream_after_response_failure(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upstream_writer = _MemoryWriter()

    async def resolve_target(_host: str, port: int) -> tuple[str, int]:
        return "203.0.113.10", port

    async def open_connection(_address: str, _port: int):
        return asyncio.StreamReader(), upstream_writer

    async def fail_response(
        _reader: asyncio.StreamReader,
        *,
        byte_limit: int,
    ) -> bytes:
        del byte_limit
        raise ValueError("invalid upstream response")

    monkeypatch.setattr(proxy_module, "resolve_target", resolve_target)
    monkeypatch.setattr(proxy_module.asyncio, "open_connection", open_connection)
    monkeypatch.setattr(proxy_module, "read_bounded_response", fail_response)
    proxy_module.POLICY = {
        "allow": ["http://example.com/status"],
        "deny": [],
        "allowed_methods": ["GET"],
        "max_exchange_seconds": 30.0,
        "max_requests": 1,
    }

    async def exercise_proxy() -> None:
        request_reader = asyncio.StreamReader()
        request_reader.feed_eof()
        with pytest.raises(ValueError, match="invalid upstream response"):
            await proxy_module.handle_http(
                "GET",
                "http://example.com/status",
                "HTTP/1.1",
                [],
                request_reader,
                _MemoryWriter(),
                sequence=1,
            )

    asyncio.run(exercise_proxy())

    assert upstream_writer.closed
    assert upstream_writer.wait_closed_calls == 1


def test_plaintext_http_closes_upstream_when_client_task_is_cancelled(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upstream_writer = _MemoryWriter()

    async def resolve_target(_host: str, port: int) -> tuple[str, int]:
        return "203.0.113.10", port

    async def open_connection(_address: str, _port: int):
        return asyncio.StreamReader(), upstream_writer

    monkeypatch.setattr(proxy_module, "resolve_target", resolve_target)
    monkeypatch.setattr(proxy_module.asyncio, "open_connection", open_connection)
    proxy_module.POLICY = {
        "allow": ["http://example.com/status"],
        "deny": [],
        "allowed_methods": ["GET"],
        "max_exchange_seconds": 30.0,
        "max_requests": 1,
    }

    async def exercise_proxy() -> None:
        response_started = asyncio.Event()

        async def block_response(
            _reader: asyncio.StreamReader,
            *,
            byte_limit: int,
        ) -> bytes:
            del byte_limit
            response_started.set()
            await asyncio.Future()
            raise AssertionError("unreachable")

        monkeypatch.setattr(proxy_module, "read_bounded_response", block_response)
        request_reader = asyncio.StreamReader()
        request_reader.feed_eof()
        task = asyncio.create_task(
            proxy_module.handle_http(
                "GET",
                "http://example.com/status",
                "HTTP/1.1",
                [],
                request_reader,
                _MemoryWriter(),
                sequence=1,
            )
        )
        await response_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise_proxy())

    assert upstream_writer.closed
    assert upstream_writer.wait_closed_calls == 1


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "100.64.0.1",
        "100.127.255.254",
        "169.254.169.254",
        "198.18.0.1",
        "2001:db8::1",
    ],
)
def test_public_only_policy_rejects_non_global_addresses(
    proxy_module: ModuleType,
    address: str,
) -> None:
    assert not proxy_module.address_allowed(address)


@pytest.mark.parametrize("address", ["8.8.8.8", "2001:4860:4860::8888"])
def test_public_only_policy_allows_global_addresses(
    proxy_module: ModuleType,
    address: str,
) -> None:
    assert proxy_module.address_allowed(address)


def test_private_network_opt_in_still_rejects_local_special_addresses(
    proxy_module: ModuleType,
) -> None:
    proxy_module.POLICY["allow_private_networks"] = True

    assert proxy_module.address_allowed("10.0.0.1")
    assert proxy_module.address_allowed("100.64.0.1")
    assert not proxy_module.address_allowed("127.0.0.1")
    assert not proxy_module.address_allowed("169.254.169.254")


@pytest.mark.parametrize(
    "field,value",
    [
        ("allow_private_networks", "false"),
        ("max_response_bytes", (8 * 1024 * 1024) + 1),
        ("max_requests", True),
        ("allowed_methods", "GET"),
        ("unsupported", True),
    ],
)
def test_proxy_policy_loader_rejects_ambiguous_or_unsafe_values(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    policy: dict[str, object] = {
        "allow": ["https://example.com/**"],
        "deny": [],
        "allowed_methods": ["GET"],
        "allow_private_networks": False,
        "max_exchange_seconds": 30.0,
        "max_response_bytes": 1_000_000,
        "max_requests": 1,
    }
    policy[field] = value
    monkeypatch.setenv(
        "PAJIN_EGRESS_POLICY_B64",
        base64.b64encode(json.dumps(policy).encode()).decode(),
    )

    with pytest.raises(RuntimeError):
        proxy_module.load_policy()


def test_proxy_policy_loader_rejects_duplicate_json_fields(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = (
        b'{"allow":["https://example.com/**"],"deny":[],'
        b'"allowed_methods":["GET"],"allow_private_networks":false,'
        b'"allow_private_networks":true,"max_response_bytes":1000000,'
        b'"max_requests":1,"max_exchange_seconds":30}'
    )
    monkeypatch.setenv("PAJIN_EGRESS_POLICY_B64", base64.b64encode(raw).decode())

    with pytest.raises(RuntimeError, match="strict JSON"):
        proxy_module.load_policy()


@pytest.mark.parametrize(
    "value",
    [None, True, "30", 0.09, 3_600.1, float("nan"), float("inf")],
)
def test_proxy_policy_requires_a_bounded_finite_numeric_exchange_deadline(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    value: object,
) -> None:
    policy = {
        "allow": ["https://example.com/**"],
        "deny": [],
        "allowed_methods": ["GET"],
        "allow_private_networks": False,
        "max_response_bytes": 1_000_000,
        "max_requests": 1,
    }
    if value is not None:
        policy["max_exchange_seconds"] = value
    monkeypatch.setenv(
        "PAJIN_EGRESS_POLICY_B64",
        base64.b64encode(json.dumps(policy).encode()).decode(),
    )

    with pytest.raises(RuntimeError):
        proxy_module.load_policy()


@pytest.mark.parametrize("seconds", [0.1, 3_600])
def test_proxy_policy_accepts_exchange_deadline_boundaries(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    seconds: float,
) -> None:
    policy = {
        "allow": ["https://example.com/**"],
        "deny": [],
        "allowed_methods": ["GET"],
        "allow_private_networks": False,
        "max_response_bytes": 1_000_000,
        "max_requests": 1,
        "max_exchange_seconds": seconds,
    }
    monkeypatch.setenv(
        "PAJIN_EGRESS_POLICY_B64",
        base64.b64encode(json.dumps(policy).encode()).decode(),
    )

    loaded = proxy_module.load_policy()

    assert loaded["max_exchange_seconds"] == seconds


def test_proxy_operation_caps_never_exceed_the_worker_exchange_deadline(
    proxy_module: ModuleType,
) -> None:
    proxy_module.POLICY["max_exchange_seconds"] = 0.1
    assert proxy_module.exchange_timeout(60.0) == 0.1
    proxy_module.POLICY["max_exchange_seconds"] = 3_600.0
    assert proxy_module.exchange_timeout(10.0) == 10.0


def test_proxy_json_receipt_skips_deep_or_oversized_json(
    proxy_module: ModuleType,
) -> None:
    nested = "0"
    for _ in range(proxy_module.MAX_JSON_DEPTH + 1):
        nested = f"[{nested}]"

    assert proxy_module.canonical_json_sha256(f'{{"value":{nested}}}'.encode()) is None
    assert (
        proxy_module.canonical_json_sha256(
            b'{"value":"' + (b"x" * proxy_module.MAX_JSON_RECEIPT_BYTES) + b'"}'
        )
        is None
    )


def test_proxy_error_log_uses_typed_code_without_reflecting_request_secrets(
    proxy_module: ModuleType,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def exercise() -> _MemoryWriter:
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET http://example.com/path?token=never-log-this HTTP/9.9\r\n\r\n")
        reader.feed_eof()
        writer = _MemoryWriter()
        await proxy_module.handle_client(reader, writer)
        return writer

    writer = asyncio.run(exercise())
    log = capsys.readouterr().err

    assert b"502 Bad Gateway" in writer.data
    assert writer.closed
    assert writer.wait_closed_calls == 1
    assert "never-log-this" not in log
    assert json.loads(log)["code"] == "invalid-request"


def test_policy_denial_closes_client_transport(
    proxy_module: ModuleType,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def exercise() -> _MemoryWriter:
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET http://denied.example/path HTTP/1.1\r\n\r\n")
        reader.feed_eof()
        writer = _MemoryWriter()
        await proxy_module.handle_client(reader, writer)
        return writer

    writer = asyncio.run(exercise())
    event = json.loads(capsys.readouterr().err)

    assert b"403 Forbidden" in writer.data
    assert writer.closed
    assert writer.wait_closed_calls == 1
    assert event["event"] == "deny"


def test_connect_receipt_states_authority_only_enforcement(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    proxy_module.POLICY = {
        "allow": ["https://example.com/**"],
        "deny": [],
        "allowed_methods": ["GET"],
        "allow_private_networks": False,
        "max_exchange_seconds": 30.0,
        "max_response_bytes": 1_000_000,
        "max_requests": 1,
    }

    async def resolve_target(_host: str, port: int) -> tuple[str, int]:
        return "203.0.113.10", port

    async def open_connection(_address: str, _port: int):
        upstream_reader = asyncio.StreamReader()
        upstream_reader.feed_eof()
        return upstream_reader, _MemoryWriter()

    monkeypatch.setattr(proxy_module, "resolve_target", resolve_target)
    monkeypatch.setattr(proxy_module.asyncio, "open_connection", open_connection)

    async def exercise() -> _MemoryWriter:
        reader = asyncio.StreamReader()
        reader.feed_eof()
        writer = _MemoryWriter()
        await proxy_module.handle_connect(
            "example.com:443",
            reader,
            writer,
            sequence=1,
        )
        return writer

    writer = asyncio.run(exercise())
    event = json.loads(capsys.readouterr().err)

    assert bytes(writer.data).startswith(b"HTTP/1.1 200 Connection Established")
    assert event["receiptEligible"] is False
    assert event["methodEnforcement"] == "trusted-worker-only"
    assert event["pathEnforcement"] == "authority-only"


def test_connect_closes_upstream_when_client_handshake_flush_fails(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy_module.POLICY = {
        "allow": ["https://example.com/**"],
        "deny": [],
        "allowed_methods": ["GET"],
        "allow_private_networks": False,
        "max_exchange_seconds": 30.0,
        "max_response_bytes": 1_000_000,
        "max_requests": 1,
    }
    upstream_writer = _MemoryWriter()

    class FailingClientWriter(_MemoryWriter):
        async def drain(self) -> None:
            raise ConnectionError("client transport failed")

    async def resolve_target(_host: str, port: int) -> tuple[str, int]:
        return "203.0.113.10", port

    async def open_connection(_address: str, _port: int):
        return asyncio.StreamReader(), upstream_writer

    monkeypatch.setattr(proxy_module, "resolve_target", resolve_target)
    monkeypatch.setattr(proxy_module.asyncio, "open_connection", open_connection)

    async def exercise() -> None:
        with pytest.raises(ConnectionError, match="client transport failed"):
            await proxy_module.handle_connect(
                "example.com:443",
                asyncio.StreamReader(),
                FailingClientWriter(),
                sequence=1,
            )

    asyncio.run(exercise())

    assert upstream_writer.closed
    assert upstream_writer.wait_closed_calls == 1


def test_connect_propagates_relay_failure_and_cancels_the_peer(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy_module.POLICY = {
        "allow": ["https://example.com/**"],
        "deny": [],
        "allowed_methods": ["GET"],
        "allow_private_networks": False,
        "max_exchange_seconds": 30.0,
        "max_response_bytes": 1_024,
        "max_requests": 1,
    }
    upstream_writer = _MemoryWriter()

    class BlockingReader:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def read(self, _size: int) -> bytes:
            self.started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled.set()
                raise
            raise AssertionError("unreachable")

    upstream_reader = BlockingReader()

    async def resolve_target(_host: str, port: int) -> tuple[str, int]:
        return "203.0.113.10", port

    async def open_connection(_address: str, _port: int):
        return upstream_reader, upstream_writer

    monkeypatch.setattr(proxy_module, "resolve_target", resolve_target)
    monkeypatch.setattr(proxy_module.asyncio, "open_connection", open_connection)

    async def exercise() -> None:
        request_reader = asyncio.StreamReader()
        request_reader.feed_data(b"x" * 2_048)
        request_reader.feed_eof()
        with pytest.raises(ValueError, match="transfer exceeded byte limit"):
            await asyncio.wait_for(
                proxy_module.handle_connect(
                    "example.com:443",
                    request_reader,
                    _MemoryWriter(),
                    sequence=1,
                ),
                timeout=0.5,
            )

    asyncio.run(exercise())

    assert upstream_reader.started.is_set()
    assert upstream_reader.cancelled.is_set()
    assert upstream_writer.closed


def test_connect_outer_cancellation_closes_both_sides_and_waits_for_close(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy_module.POLICY = {
        "allow": ["https://example.com/**"],
        "deny": [],
        "allowed_methods": ["GET"],
        "allow_private_networks": False,
        "max_exchange_seconds": 30.0,
        "max_response_bytes": 1_024,
        "max_requests": 1,
    }

    class BlockingReader:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def read(self, _size: int) -> bytes:
            self.started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled.set()
                raise
            raise AssertionError("unreachable")

    client_reader = BlockingReader()
    upstream_reader = BlockingReader()
    client_writer = _MemoryWriter()
    upstream_writer = _MemoryWriter()

    async def resolve_target(_host: str, port: int) -> tuple[str, int]:
        return "203.0.113.10", port

    async def open_connection(_address: str, _port: int):
        return upstream_reader, upstream_writer

    monkeypatch.setattr(proxy_module, "resolve_target", resolve_target)
    monkeypatch.setattr(proxy_module.asyncio, "open_connection", open_connection)

    async def exercise() -> None:
        task = asyncio.create_task(
            proxy_module.handle_connect(
                "example.com:443",
                client_reader,
                client_writer,
                sequence=1,
            )
        )
        await asyncio.wait_for(
            asyncio.gather(client_reader.started.wait(), upstream_reader.started.wait()),
            timeout=0.5,
        )
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())

    assert client_reader.cancelled.is_set()
    assert upstream_reader.cancelled.is_set()
    assert client_writer.closed
    assert client_writer.wait_closed_calls == 1
    assert upstream_writer.closed
    assert upstream_writer.wait_closed_calls == 1


def test_plaintext_http_bounds_a_silent_upstream_response(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy_module.POLICY = {
        "allow": ["http://example.com/status"],
        "deny": [],
        "allowed_methods": ["GET"],
        "allow_private_networks": False,
        "max_exchange_seconds": 30.0,
        "max_response_bytes": 1_024,
        "max_requests": 1,
    }
    monkeypatch.setattr(proxy_module, "UPSTREAM_IO_TIMEOUT_SECONDS", 0.01)
    upstream_writer = _MemoryWriter()

    async def resolve_target(_host: str, port: int) -> tuple[str, int]:
        return "203.0.113.10", port

    async def open_connection(_address: str, _port: int):
        return asyncio.StreamReader(), upstream_writer

    monkeypatch.setattr(proxy_module, "resolve_target", resolve_target)
    monkeypatch.setattr(proxy_module.asyncio, "open_connection", open_connection)

    async def exercise() -> None:
        request_reader = asyncio.StreamReader()
        request_reader.feed_eof()
        with pytest.raises(TimeoutError):
            await proxy_module.handle_http(
                "GET",
                "http://example.com/status",
                "HTTP/1.1",
                [],
                request_reader,
                _MemoryWriter(),
                sequence=1,
            )

    asyncio.run(exercise())

    assert upstream_writer.closed
    assert upstream_writer.wait_closed_calls == 1


def test_client_header_read_has_a_deadline_and_typed_audit_code(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(proxy_module, "CLIENT_HEADER_TIMEOUT_SECONDS", 0.01)

    async def exercise() -> _MemoryWriter:
        writer = _MemoryWriter()
        await proxy_module.handle_client(asyncio.StreamReader(), writer)
        return writer

    writer = asyncio.run(exercise())
    event = json.loads(capsys.readouterr().err)

    assert event["code"] == "client-timeout"
    assert b"502 Bad Gateway" in writer.data
    assert writer.closed
    assert writer.wait_closed_calls == 1


def test_blocked_error_response_drain_is_bounded_and_closes_client(
    proxy_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(proxy_module, "CLIENT_IO_TIMEOUT_SECONDS", 0.01)

    class BlockingWriter(_MemoryWriter):
        def __init__(self) -> None:
            super().__init__()
            self.cancelled_drains = 0

        async def drain(self) -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled_drains += 1
                raise

    async def exercise() -> BlockingWriter:
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET http://denied.example/path HTTP/1.1\r\n\r\n")
        reader.feed_eof()
        writer = BlockingWriter()
        await proxy_module.handle_client(reader, writer)
        return writer

    writer = asyncio.run(asyncio.wait_for(exercise(), timeout=0.5))
    event = json.loads(capsys.readouterr().err)

    assert event["code"] == "client-timeout"
    assert writer.cancelled_drains == 2
    assert writer.closed
    assert writer.wait_closed_calls == 1
