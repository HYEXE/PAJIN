"""Per-execution HTTP/HTTPS allowlist proxy for PAJIN development workers."""

import asyncio
import ipaddress
import json
import os
import socket
import sys
from base64 import b64decode
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

MAX_HEADER_BYTES = 65_536
MAX_REQUEST_BODY_BYTES = 1_000_000
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def load_policy() -> dict[str, Any]:
    encoded = os.environ.get("PAJIN_EGRESS_POLICY_B64", "")
    if not encoded:
        raise RuntimeError("PAJIN_EGRESS_POLICY_B64 is required")
    policy = json.loads(b64decode(encoded).decode("utf-8"))
    if not policy.get("allow"):
        raise RuntimeError("at least one allow rule is required")
    return policy


POLICY = load_policy()


def log_event(event: str, **fields: object) -> None:
    print(
        json.dumps({"event": event, **fields}, separators=(",", ":")),
        file=sys.stderr,
        flush=True,
    )


def parse_url(value: str) -> SplitResult:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("unsupported or incomplete URL")
    if parsed.username or parsed.password:
        raise ValueError("URL credentials are forbidden")
    return parsed


def authority_matches(pattern: SplitResult, target: SplitResult) -> bool:
    if pattern.scheme != target.scheme:
        return False
    pattern_host = pattern.hostname or ""
    target_host = target.hostname or ""
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
    pattern = parse_url(pattern_value)
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


def audit_target(target_url: str) -> str:
    """Keep route evidence while avoiding query-value disclosure in logs."""

    parsed = parse_url(target_url)
    query = "<redacted>" if parsed.query else ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def request_allowed(method: str, target_url: str, *, authority_only: bool) -> bool:
    if method.upper() != "CONNECT" and method.upper() not in set(POLICY.get("allowed_methods", [])):
        return False
    deny_rules = POLICY.get("deny", [])
    if authority_only:
        target = parse_url(target_url)
        # CONNECT hides the HTTP path and method inside TLS. Any deny rule for
        # the authority therefore denies the whole tunnel. Likewise, only a
        # host-wide allow pattern can safely authorize a tunnel.
        if any(authority_matches(parse_url(rule), target) for rule in deny_rules):
            return False
        return any(
            authority_matches(pattern, target) and (pattern.path or "/") in {"/*", "/**"}
            for pattern in (parse_url(rule) for rule in POLICY["allow"])
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
    return not ip.is_private or bool(POLICY.get("allow_private_networks", False))


async def resolve_target(host: str, port: int) -> tuple[str, int]:
    loop = asyncio.get_running_loop()
    results = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
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
    await writer.drain()


async def read_headers(reader: asyncio.StreamReader) -> tuple[str, list[tuple[str, str]]]:
    request_line = await reader.readline()
    if not request_line:
        return "", []
    total = len(request_line)
    headers: list[tuple[str, str]] = []
    while True:
        line = await reader.readline()
        total += len(line)
        if total > MAX_HEADER_BYTES:
            raise ValueError("request headers exceed limit")
        if line in {b"\r\n", b"\n", b""}:
            break
        name, separator, value = line.decode("latin-1").partition(":")
        if not separator:
            raise ValueError("malformed header")
        headers.append((name.strip(), value.strip()))
    return request_line.decode("latin-1").strip(), headers


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
        writer.close()


async def handle_connect(
    authority: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    parsed_authority = urlsplit(f"//{authority}")
    host = parsed_authority.hostname
    port = parsed_authority.port or 443
    if not host:
        raise ValueError("CONNECT host is missing")
    target_url = urlunsplit(("https", f"{host}:{port}", "/", "", ""))
    if not request_allowed("CONNECT", target_url, authority_only=True):
        await send_error(writer, 403, "Forbidden")
        log_event("deny", method="CONNECT", authority=authority)
        return
    address, port = await resolve_target(host, port)
    upstream_reader, upstream_writer = await asyncio.open_connection(address, port)
    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await writer.drain()
    log_event("allow", method="CONNECT", authority=authority, address=address)
    byte_limit = int(POLICY.get("max_response_bytes", 10_000_000))
    await asyncio.gather(
        relay(reader, upstream_writer, byte_limit=byte_limit),
        relay(upstream_reader, writer, byte_limit=byte_limit),
        return_exceptions=True,
    )


async def handle_http(
    method: str,
    target_url: str,
    version: str,
    headers: list[tuple[str, str]],
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    if not request_allowed(method, target_url, authority_only=False):
        await send_error(writer, 403, "Forbidden")
        log_event("deny", method=method, target=audit_target(target_url))
        return
    parsed = parse_url(target_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme != "http":
        await send_error(writer, 400, "Use CONNECT for HTTPS")
        return
    address, port = await resolve_target(parsed.hostname or "", port)
    upstream_reader, upstream_writer = await asyncio.open_connection(address, port)
    path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    filtered = [(name, value) for name, value in headers if name.lower() not in HOP_BY_HOP]
    host_value = parsed.hostname or ""
    if parsed.port and parsed.port != 80:
        host_value = f"{host_value}:{parsed.port}"
    filtered = [(name, value) for name, value in filtered if name.lower() != "host"]
    filtered.append(("Host", host_value))
    filtered.append(("Connection", "close"))
    upstream_writer.write(f"{method} {path} {version}\r\n".encode("latin-1"))
    for name, value in filtered:
        upstream_writer.write(f"{name}: {value}\r\n".encode("latin-1"))
    upstream_writer.write(b"\r\n")

    content_length = next(
        (int(value) for name, value in headers if name.lower() == "content-length"),
        0,
    )
    if content_length > MAX_REQUEST_BODY_BYTES:
        upstream_writer.close()
        await send_error(writer, 413, "Payload Too Large")
        return
    if content_length:
        upstream_writer.write(await reader.readexactly(content_length))
    await upstream_writer.drain()
    log_event("allow", method=method, target=audit_target(target_url), address=address)
    await relay(
        upstream_reader,
        writer,
        byte_limit=int(POLICY.get("max_response_bytes", 10_000_000)),
    )


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request_line, headers = await read_headers(reader)
        if not request_line:
            writer.close()
            return
        method, target, version = request_line.split(" ", 2)
        if method.upper() == "CONNECT":
            await handle_connect(target, reader, writer)
        else:
            await handle_http(method.upper(), target, version, headers, reader, writer)
    except (ValueError, OSError, asyncio.IncompleteReadError, PermissionError) as exc:
        log_event("error", error=str(exc))
        if not writer.is_closing():
            await send_error(writer, 502, "Bad Gateway")
            writer.close()


async def main() -> None:
    server = await asyncio.start_server(handle_client, "0.0.0.0", 8080, limit=MAX_HEADER_BYTES)
    log_event("ready", port=8080)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
