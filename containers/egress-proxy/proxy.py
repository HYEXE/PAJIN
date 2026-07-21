"""Per-execution HTTP/HTTPS allowlist proxy for PAJIN development workers."""

import asyncio
import binascii
import ipaddress
import json
import math
import os
import socket
import sys
from base64 import b64decode
from contextlib import suppress
from fnmatch import fnmatchcase
from hashlib import sha256
from re import Match
from re import compile as compile_pattern
from typing import Any
from urllib.parse import SplitResult, quote, unquote, unquote_to_bytes, urlsplit, urlunsplit

MAX_HEADER_BYTES = 65_536
MAX_REQUEST_BODY_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_POLICY_BYTES = 256 * 1024
MAX_JSON_RECEIPT_BYTES = 1 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 20_000
STREAM_CLOSE_TIMEOUT_SECONDS = 1.0
CLIENT_HEADER_TIMEOUT_SECONDS = 10.0
CLIENT_IO_TIMEOUT_SECONDS = 5.0
UPSTREAM_CONNECT_TIMEOUT_SECONDS = 10.0
UPSTREAM_IO_TIMEOUT_SECONDS = 30.0
CONNECT_TUNNEL_TIMEOUT_SECONDS = 60.0
RECEIPT_VERSION = "pajin.dev/egress-http-json-receipt/v1"
VALID_PERCENT_ESCAPE = compile_pattern(r"%[0-9A-Fa-f]{2}")
INVALID_PERCENT_ESCAPE = compile_pattern(r"%(?![0-9A-Fa-f]{2})")
HTTP_TOKEN = compile_pattern(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
URI_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
REQUEST_COUNT = 0


class ClientTimeoutError(TimeoutError):
    """A timeout caused by the Worker-side proxy connection."""


def _strict_json_object(raw: bytes, *, max_bytes: int) -> dict[str, Any] | None:
    if len(raw) > max_bytes:
        return None

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant is forbidden: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON object key")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return None
    if not isinstance(value, dict):
        return None

    nodes = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            return None
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def _policy_string_list(policy: dict[str, Any], name: str, *, required: bool) -> list[str]:
    value = policy.get(name, [] if not required else None)
    if not isinstance(value, list) or (required and not value) or len(value) > 1_000:
        raise RuntimeError(f"egress policy {name} must be a bounded JSON list")
    if not all(isinstance(item, str) and 0 < len(item) <= 4_096 for item in value):
        raise RuntimeError(f"egress policy {name} contains an invalid rule")
    if len(set(value)) != len(value):
        raise RuntimeError(f"egress policy {name} contains duplicate rules")
    return value


def _policy_exchange_seconds(value: object) -> float:
    if type(value) not in {int, float}:
        raise RuntimeError("max_exchange_seconds must be a JSON number")
    assert isinstance(value, (int, float))
    seconds = float(value)
    if not math.isfinite(seconds) or not 0.1 <= seconds <= 3_600:
        raise RuntimeError("max_exchange_seconds must be between 0.1 and 3600")
    return seconds


def load_policy() -> dict[str, Any]:
    encoded = os.environ.get("PAJIN_EGRESS_POLICY_B64", "")
    if not encoded or len(encoded) > (MAX_POLICY_BYTES * 2):
        raise RuntimeError("PAJIN_EGRESS_POLICY_B64 is required")
    try:
        raw = b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("egress policy encoding is invalid") from exc
    policy = _strict_json_object(raw, max_bytes=MAX_POLICY_BYTES)
    if policy is None:
        raise RuntimeError("egress policy must be bounded strict JSON")
    supported_fields = {
        "allow",
        "deny",
        "allowed_methods",
        "allow_private_networks",
        "max_exchange_seconds",
        "max_response_bytes",
        "max_requests",
    }
    if not set(policy).issubset(supported_fields):
        raise RuntimeError("egress policy contains unsupported fields")

    allow = _policy_string_list(policy, "allow", required=True)
    deny = _policy_string_list(policy, "deny", required=False)
    methods = _policy_string_list(policy, "allowed_methods", required=True)
    if len(methods) > 32 or any(
        len(method) > 32 or HTTP_TOKEN.fullmatch(method) is None or method != method.upper()
        for method in methods
    ):
        raise RuntimeError("egress policy allowed_methods is invalid")
    allow_private_networks = policy.get("allow_private_networks", False)
    if not isinstance(allow_private_networks, bool):
        raise RuntimeError("allow_private_networks must be boolean")
    max_requests = policy.get("max_requests", 1)
    if isinstance(max_requests, bool) or not isinstance(max_requests, int):
        raise RuntimeError("max_requests must be an integer")
    if not 1 <= max_requests <= 100:
        raise RuntimeError("max_requests must be between 1 and 100")
    max_response_bytes = policy.get("max_response_bytes", MAX_RESPONSE_BYTES)
    if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int):
        raise RuntimeError("max_response_bytes must be an integer")
    if not 1_024 <= max_response_bytes <= MAX_RESPONSE_BYTES:
        raise RuntimeError(f"max_response_bytes must be between 1024 and {MAX_RESPONSE_BYTES}")
    max_exchange_seconds = _policy_exchange_seconds(policy.get("max_exchange_seconds"))

    for rule in [*allow, *deny]:
        parse_url(rule, pattern=True)
    return {
        "allow": allow,
        "deny": deny,
        "allowed_methods": methods,
        "allow_private_networks": allow_private_networks,
        "max_exchange_seconds": max_exchange_seconds,
        "max_response_bytes": max_response_bytes,
        "max_requests": max_requests,
    }


def log_event(event: str, **fields: object) -> None:
    print(
        json.dumps({"event": event, **fields}, separators=(",", ":")),
        file=sys.stderr,
        flush=True,
    )


def _safe_proxy_error_code(exc: BaseException) -> str:
    if isinstance(exc, PermissionError):
        return "policy-denied"
    if isinstance(exc, asyncio.IncompleteReadError):
        return "incomplete-request"
    if isinstance(exc, ClientTimeoutError):
        return "client-timeout"
    if isinstance(exc, TimeoutError):
        return "upstream-timeout"
    if isinstance(exc, OSError):
        return "network-io-failed"
    return "invalid-request"


def parse_url(value: str, *, pattern: bool = False) -> SplitResult:
    if _contains_control_characters(value):
        raise ValueError("URL contains control characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL port is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("unsupported or incomplete URL")
    if parsed.username or parsed.password:
        raise ValueError("URL credentials are forbidden")
    if parsed.fragment:
        raise ValueError("URL fragments are not enforceable")
    hostname = parsed.hostname
    wildcard_count = hostname.count("*")
    if pattern:
        if wildcard_count and (wildcard_count != 1 or not hostname.startswith("*.")):
            raise ValueError("only one leading hostname wildcard is supported")
    elif wildcard_count:
        raise ValueError("target URL cannot contain a wildcard")
    hostname = _canonical_hostname(hostname, pattern=pattern)
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError("URL port must be between 1 and 65535")
    normalized_path = _normalize_unambiguous_path(parsed.path or "/")
    authority_host = f"[{hostname}]" if ":" in hostname else hostname
    authority = authority_host if port is None else f"{authority_host}:{port}"
    return parsed._replace(
        netloc=authority,
        path=normalized_path,
        query=_normalize_query(parsed.query),
    )


def _contains_control_characters(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _validate_path_representation(path: str, *, raw_slash_count: int) -> None:
    if _contains_control_characters(path):
        raise ValueError("URL path contains a control character")
    if "\\" in path:
        raise ValueError("URL path contains an ambiguous backslash")
    if path.count("/") != raw_slash_count:
        raise ValueError("URL path contains an encoded slash")
    if any(segment.partition(";")[0] in {".", ".."} for segment in path.split("/")):
        raise ValueError("URL path contains an ambiguous traversal segment")


def _normalize_unambiguous_path(path: str) -> str:
    """Reject path spellings that HTTP servers commonly canonicalize differently."""

    if INVALID_PERCENT_ESCAPE.search(path):
        raise ValueError("URL path contains malformed percent-encoding")

    raw_slash_count = path.count("/")
    _validate_path_representation(path, raw_slash_count=raw_slash_count)
    try:
        decoded = unquote(path, errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("URL path contains invalid percent-encoding") from exc
    _validate_path_representation(decoded, raw_slash_count=raw_slash_count)
    if VALID_PERCENT_ESCAPE.search(decoded) is not None:
        raise ValueError("URL path contains nested percent-encoding")
    return quote(
        decoded,
        safe="/:@-._~!$&'()*+,;=",
        encoding="utf-8",
        errors="strict",
    )


def _canonical_hostname(hostname: str, *, pattern: bool) -> str:
    if "%" in hostname or hostname.endswith(".."):
        raise ValueError("URL hostname contains an ambiguous representation")
    rooted = hostname[:-1] if hostname.endswith(".") else hostname
    wildcard = pattern and rooted.startswith("*.")
    suffix = rooted[2:] if wildcard else rooted
    if not suffix:
        raise ValueError("URL hostname is required")
    try:
        canonical = suffix.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("URL hostname is not valid IDNA text") from exc
    if len(canonical) > 253:
        raise ValueError("URL hostname is too long")
    return f"*.{canonical}" if wildcard else canonical


def _normalize_query(query: str) -> str:
    if not query:
        return ""
    if INVALID_PERCENT_ESCAPE.search(query):
        raise ValueError("URL query contains malformed percent-encoding")
    decoded_bytes = unquote_to_bytes(query)
    if VALID_PERCENT_ESCAPE.search(decoded_bytes.decode("latin-1")) is not None:
        raise ValueError("URL query contains nested percent-encoding")

    def normalize_escape(match: Match[str]) -> str:
        encoded = match.group(0)
        character = chr(int(encoded[1:], 16))
        return character if character in URI_UNRESERVED else encoded.upper()

    normalized = VALID_PERCENT_ESCAPE.sub(normalize_escape, query)
    return quote(
        normalized,
        safe="!$&'()*+,;=:@/?-._~%",
        encoding="utf-8",
        errors="strict",
    )


def authority_matches(pattern: SplitResult, target: SplitResult) -> bool:
    if pattern.scheme != target.scheme:
        return False
    pattern_host = _canonical_hostname(pattern.hostname or "", pattern=True)
    target_host = _canonical_hostname(target.hostname or "", pattern=False)
    if pattern_host.startswith("*."):
        suffix = pattern_host[1:].lower()
        if not target_host.lower().endswith(suffix) or target_host.lower() == suffix[1:]:
            return False
    elif pattern_host.lower() != target_host.lower():
        return False
    pattern_port = pattern.port or (443 if pattern.scheme == "https" else 80)
    target_port = target.port or (443 if target.scheme == "https" else 80)
    return pattern_port == target_port


def scope_matches(pattern_value: str, target_value: str, *, authority_only: bool) -> bool:
    pattern = parse_url(pattern_value, pattern=True)
    target = parse_url(target_value)
    if not authority_matches(pattern, target):
        return False
    if authority_only:
        return True
    pattern_path = pattern.path or "/"
    target_path = target.path or "/"
    if not fnmatchcase(target_path, pattern_path):
        return False
    return not pattern.query or pattern.query == target.query


POLICY = load_policy()


def exchange_timeout(cap_seconds: float) -> float:
    """Cap one internal operation by the authoritative Worker job deadline."""

    return min(cap_seconds, float(POLICY["max_exchange_seconds"]))


def audit_target(target_url: str) -> str:
    """Keep route evidence while avoiding query-value disclosure in logs."""

    parsed = parse_url(target_url)
    hostname = parsed.hostname or ""
    authority_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if parsed.scheme == "https" else 80
    authority = (
        authority_host if parsed.port in {None, default_port} else f"{authority_host}:{parsed.port}"
    )
    query = "<redacted>" if parsed.query else ""
    return urlunsplit((parsed.scheme, authority, parsed.path, query, ""))


def request_allowed(method: str, target_url: str, *, authority_only: bool) -> bool:
    if method.upper() != "CONNECT" and method.upper() not in set(POLICY.get("allowed_methods", [])):
        return False
    deny_rules = POLICY.get("deny", [])
    if authority_only:
        target = parse_url(target_url)
        # CONNECT hides the HTTP path and method inside TLS. Any deny rule for
        # the authority therefore denies the whole tunnel. Likewise, only a
        # host-wide allow pattern can safely authorize a tunnel.
        if any(authority_matches(parse_url(rule, pattern=True), target) for rule in deny_rules):
            return False
        return any(
            authority_matches(pattern, target)
            and (pattern.path or "/") in {"/*", "/**"}
            and not pattern.query
            for pattern in (parse_url(rule, pattern=True) for rule in POLICY["allow"])
        )
    for rule in deny_rules:
        if scope_matches(rule, target_url, authority_only=authority_only):
            return False
    return any(
        scope_matches(rule, target_url, authority_only=authority_only) for rule in POLICY["allow"]
    )


def address_allowed(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    if POLICY.get("allow_private_networks", False):
        return True
    # ``is_private`` is not the inverse of Internet routability. For example,
    # the shared CGNAT range (100.64.0.0/10) is neither private nor global.
    # A public-only policy must therefore require a globally routable address
    # instead of merely excluding addresses classified as private.
    return ip.is_global


async def resolve_target(host: str, port: int) -> tuple[str, int]:
    loop = asyncio.get_running_loop()
    results = await asyncio.wait_for(
        loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
        timeout=exchange_timeout(UPSTREAM_CONNECT_TIMEOUT_SECONDS),
    )
    addresses = {item[4][0] for item in results}
    if not addresses or any(not address_allowed(address) for address in addresses):
        raise PermissionError("DNS result contains a prohibited address")
    return sorted(addresses)[0], port


async def send_error(writer: asyncio.StreamWriter, status: int, message: str) -> None:
    body = f"{status} {message}\n".encode()
    response_headers = (
        f"HTTP/1.1 {status} {message}\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n"
    )
    writer.write(response_headers.encode() + body)
    await drain_client(writer)


async def drain_client(writer: asyncio.StreamWriter) -> None:
    try:
        await asyncio.wait_for(
            writer.drain(),
            timeout=exchange_timeout(CLIENT_IO_TIMEOUT_SECONDS),
        )
    except TimeoutError as exc:
        raise ClientTimeoutError from exc


async def close_writer(writer: asyncio.StreamWriter) -> None:
    """Close a stream and bound best-effort transport shutdown.

    ``close()`` is synchronous but the underlying socket may remain owned by
    the event loop until ``wait_closed()`` completes. Cleanup failures must not
    replace the exchange's authoritative success, protocol error, or
    cancellation.
    """

    writer.close()
    # Cancellation derives from BaseException and is deliberately not
    # swallowed. Ordinary close errors and timeouts are cleanup-only.
    with suppress(Exception):
        await asyncio.wait_for(
            writer.wait_closed(),
            timeout=exchange_timeout(STREAM_CLOSE_TIMEOUT_SECONDS),
        )


async def read_headers(reader: asyncio.StreamReader) -> tuple[str, list[tuple[str, str]]]:
    request_line = await reader.readline()
    if not request_line:
        return "", []
    if len(request_line) > MAX_HEADER_BYTES or not request_line.endswith(b"\r\n"):
        raise ValueError("request line is malformed or exceeds limit")
    total = len(request_line)
    headers: list[tuple[str, str]] = []
    while True:
        line = await reader.readline()
        total += len(line)
        if total > MAX_HEADER_BYTES:
            raise ValueError("request headers exceed limit")
        if line == b"":
            raise ValueError("request headers are incomplete")
        if line == b"\r\n":
            break
        if not line.endswith(b"\r\n") or line.startswith((b" ", b"\t")):
            raise ValueError("request header line is malformed")
        name, separator, value = line[:-2].decode("latin-1").partition(":")
        if (
            not separator
            or not name
            or len(name) > 128
            or HTTP_TOKEN.fullmatch(name) is None
            or _contains_control_characters(value)
        ):
            raise ValueError("malformed header")
        headers.append((name, value.strip(" ")))
        if len(headers) > 100:
            raise ValueError("request contains too many headers")
    return request_line[:-2].decode("latin-1"), headers


def reserve_request() -> int:
    """Return the one-based proxy request sequence or reject budget overflow."""

    global REQUEST_COUNT
    REQUEST_COUNT += 1
    if int(POLICY.get("max_requests", 1)) < REQUEST_COUNT:
        raise PermissionError("egress request count exceeded policy")
    return REQUEST_COUNT


def content_length(headers: list[tuple[str, str]]) -> int:
    values = [value for name, value in headers if name.lower() == "content-length"]
    if len(values) > 1:
        raise ValueError("duplicate Content-Length headers are forbidden")
    transfer_encodings = [value for name, value in headers if name.lower() == "transfer-encoding"]
    if transfer_encodings:
        raise ValueError("Transfer-Encoding request bodies are unsupported")
    if not values:
        return 0
    value = values[0]
    if not value.isascii() or not value.isdecimal():
        raise ValueError("Content-Length must be a non-negative decimal integer")
    length = int(value)
    if length > MAX_REQUEST_BODY_BYTES:
        raise ValueError("request body exceeded byte limit")
    return length


def canonical_json_sha256(raw: bytes) -> str | None:
    value = _strict_json_object(raw, max_bytes=MAX_JSON_RECEIPT_BYTES)
    if value is None:
        return None
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


async def read_bounded_response(reader: asyncio.StreamReader, *, byte_limit: int) -> bytes:
    chunks: list[bytes] = []
    transferred = 0
    while data := await reader.read(16_384):
        transferred += len(data)
        if transferred > byte_limit:
            raise ValueError("proxy response exceeded byte limit")
        chunks.append(data)
    return b"".join(chunks)


def response_json_receipt(response: bytes) -> tuple[int, str, str | None] | None:
    header_end = response.find(b"\r\n\r\n")
    if header_end < 0:
        return None
    header_lines = response[:header_end].split(b"\r\n")
    try:
        _http_version, raw_status, _reason = header_lines[0].decode("latin-1").split(" ", 2)
        status = int(raw_status)
    except (IndexError, ValueError):
        return None
    headers: list[tuple[str, str]] = []
    for line in header_lines[1:]:
        name, separator, value = line.decode("latin-1").partition(":")
        if not separator:
            return None
        headers.append((name.strip(), value.strip()))
    lengths = [value for name, value in headers if name.lower() == "content-length"]
    if len(lengths) > 1:
        return None
    if any(name.lower() == "transfer-encoding" for name, _value in headers):
        return None
    body = response[header_end + 4 :]
    if lengths:
        if not lengths[0].isascii() or not lengths[0].isdecimal():
            return None
        if int(lengths[0]) != len(body):
            return None
    digest = canonical_json_sha256(body)
    return status, sha256(body).hexdigest(), digest


async def relay(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    byte_limit: int,
) -> None:
    transferred = 0
    try:
        while data := await reader.read(16_384):
            transferred += len(data)
            if transferred > byte_limit:
                raise ValueError("proxy transfer exceeded byte limit")
            writer.write(data)
            await writer.drain()
    finally:
        await close_writer(writer)


async def relay_tunnel(
    reader: asyncio.StreamReader,
    upstream_reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    upstream_writer: asyncio.StreamWriter,
    *,
    byte_limit: int,
) -> None:
    """Relay both tunnel directions and never detach the surviving peer."""

    tasks = (
        asyncio.create_task(relay(reader, upstream_writer, byte_limit=byte_limit)),
        asyncio.create_task(relay(upstream_reader, writer, byte_limit=byte_limit)),
    )
    try:
        done, _pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        # A byte-limit or transport error is authoritative. Inspect every task
        # that completed in the same loop turn before terminating the peer.
        for task in done:
            task.result()
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def handle_connect(
    authority: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    sequence: int,
) -> None:
    if _contains_control_characters(authority):
        raise ValueError("CONNECT authority contains control characters")
    try:
        parsed_authority = urlsplit(f"//{authority}")
        explicit_port = parsed_authority.port
    except ValueError as exc:
        raise ValueError("CONNECT authority port is invalid") from exc
    host = parsed_authority.hostname
    if (
        not host
        or parsed_authority.username
        or parsed_authority.password
        or parsed_authority.path
        or parsed_authority.query
        or parsed_authority.fragment
    ):
        raise ValueError("CONNECT target must be a bare host authority")
    if explicit_port == 0:
        raise ValueError("CONNECT port 0 is not allowed")
    port = explicit_port or 443
    target_host = f"[{host}]" if ":" in host else host
    target_url = urlunsplit(("https", f"{target_host}:{port}", "/", "", ""))
    if not request_allowed("CONNECT", target_url, authority_only=True):
        await send_error(writer, 403, "Forbidden")
        log_event("deny", method="CONNECT", authority=authority)
        return
    address, port = await resolve_target(host, port)
    upstream_reader, upstream_writer = await asyncio.wait_for(
        asyncio.open_connection(address, port),
        timeout=exchange_timeout(UPSTREAM_CONNECT_TIMEOUT_SECONDS),
    )
    try:
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await drain_client(writer)
        log_event(
            "allow",
            sequence=sequence,
            method="CONNECT",
            authority=authority,
            address=address,
            receiptEligible=False,
            methodEnforcement="trusted-worker-only",
            pathEnforcement="authority-only",
        )
        byte_limit = int(POLICY.get("max_response_bytes", MAX_RESPONSE_BYTES))
        await asyncio.wait_for(
            relay_tunnel(
                reader,
                upstream_reader,
                writer,
                upstream_writer,
                byte_limit=byte_limit,
            ),
            timeout=exchange_timeout(CONNECT_TUNNEL_TIMEOUT_SECONDS),
        )
    finally:
        # A client-side handshake failure or cancellation can happen before
        # either relay coroutine starts and takes ownership of this writer.
        # Always release the already-opened upstream transport in that gap.
        if not upstream_writer.is_closing():
            await close_writer(upstream_writer)


async def handle_http(
    method: str,
    target_url: str,
    version: str,
    headers: list[tuple[str, str]],
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    sequence: int,
) -> None:
    if not request_allowed(method, target_url, authority_only=False):
        await send_error(writer, 403, "Forbidden")
        log_event("deny", method=method, target=audit_target(target_url))
        return
    body_length = content_length(headers)
    parsed = parse_url(target_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme != "http":
        await send_error(writer, 400, "Use CONNECT for HTTPS")
        return
    address, port = await resolve_target(parsed.hostname or "", port)
    upstream_reader, upstream_writer = await asyncio.wait_for(
        asyncio.open_connection(address, port),
        timeout=exchange_timeout(UPSTREAM_CONNECT_TIMEOUT_SECONDS),
    )
    try:
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection_tokens = {
            token.strip().lower()
            for name, value in headers
            if name.lower() == "connection"
            for token in value.split(",")
            if token.strip()
        }
        if any(HTTP_TOKEN.fullmatch(token) is None for token in connection_tokens):
            raise ValueError("Connection header contains an invalid token")
        filtered = [
            (name, value)
            for name, value in headers
            if name.lower() not in HOP_BY_HOP | connection_tokens
        ]
        host_value = parsed.hostname or ""
        if ":" in host_value:
            host_value = f"[{host_value}]"
        if parsed.port and parsed.port != 80:
            host_value = f"{host_value}:{parsed.port}"
        filtered = [(name, value) for name, value in filtered if name.lower() != "host"]
        filtered.append(("Host", host_value))
        filtered.append(("Connection", "close"))
        upstream_writer.write(f"{method} {path} {version}\r\n".encode("latin-1"))
        for name, value in filtered:
            upstream_writer.write(f"{name}: {value}\r\n".encode("latin-1"))
        upstream_writer.write(b"\r\n")

        request_body = (
            await asyncio.wait_for(
                reader.readexactly(body_length),
                timeout=exchange_timeout(UPSTREAM_IO_TIMEOUT_SECONDS),
            )
            if body_length
            else b""
        )
        if request_body:
            upstream_writer.write(request_body)
        await asyncio.wait_for(
            upstream_writer.drain(),
            timeout=exchange_timeout(UPSTREAM_IO_TIMEOUT_SECONDS),
        )
        response = await asyncio.wait_for(
            read_bounded_response(
                upstream_reader,
                byte_limit=int(POLICY.get("max_response_bytes", MAX_RESPONSE_BYTES)),
            ),
            timeout=exchange_timeout(UPSTREAM_IO_TIMEOUT_SECONDS),
        )
    finally:
        await close_writer(upstream_writer)

    receipt = response_json_receipt(response) if method in {"GET", "POST"} else None
    request_digest = canonical_json_sha256(request_body) if method == "POST" else None
    if receipt is not None and (method == "GET" or request_digest is not None):
        status, response_body_digest, response_json_digest = receipt
        fields: dict[str, object] = {
            "receiptVersion": RECEIPT_VERSION,
            "sequence": sequence,
            "method": method,
            "target": audit_target(target_url),
            "targetSha256": sha256(target_url.encode("utf-8")).hexdigest(),
            "address": address,
            "status": status,
            "responseBodySha256": response_body_digest,
        }
        if response_json_digest is not None:
            fields["responseJsonSha256"] = response_json_digest
        if request_digest is not None:
            fields["requestJsonSha256"] = request_digest
        log_event("allow", **fields)
    else:
        log_event(
            "allow",
            sequence=sequence,
            method=method,
            target=audit_target(target_url),
            address=address,
            receiptEligible=False,
        )

    # The host treats this flushed log record as the terminal observation for
    # the exchange. Publish it before the Worker can consume the final response
    # and exit, otherwise Docker log collection can race ahead of the receipt.
    writer.write(response)
    await drain_client(writer)
    writer.close()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        try:
            request_line, headers = await asyncio.wait_for(
                read_headers(reader),
                timeout=exchange_timeout(CLIENT_HEADER_TIMEOUT_SECONDS),
            )
        except TimeoutError as exc:
            raise ClientTimeoutError from exc
        if not request_line:
            return
        parts = request_line.split(" ")
        if len(parts) != 3 or not all(parts):
            raise ValueError("request line must contain exactly three fields")
        method, target, version = parts
        if (
            len(method) > 32
            or HTTP_TOKEN.fullmatch(method) is None
            or method != method.upper()
            or version not in {"HTTP/1.0", "HTTP/1.1"}
        ):
            raise ValueError("request method or HTTP version is invalid")
        try:
            sequence = reserve_request()
        except PermissionError:
            await send_error(writer, 429, "Too Many Requests")
            log_event("deny", method=method.upper(), reason="request-count")
            return
        if method.upper() == "CONNECT":
            await handle_connect(target, reader, writer, sequence=sequence)
        else:
            await handle_http(
                method.upper(),
                target,
                version,
                headers,
                reader,
                writer,
                sequence=sequence,
            )
    except (ValueError, OSError, asyncio.IncompleteReadError, PermissionError) as exc:
        log_event("error", code=_safe_proxy_error_code(exc))
        if not writer.is_closing():
            with suppress(Exception):
                await send_error(writer, 502, "Bad Gateway")
    finally:
        await close_writer(writer)


async def main() -> None:
    server = await asyncio.start_server(handle_client, "0.0.0.0", 8080, limit=MAX_HEADER_BYTES)
    log_event("ready", port=8080)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
