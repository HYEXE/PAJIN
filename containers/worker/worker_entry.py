"""Minimal PAJIN development worker image entrypoint."""

import errno
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import time
from base64 import b64encode, urlsafe_b64encode
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from http.client import HTTPResponse, HTTPSConnection
from ipaddress import ip_address
from re import fullmatch
from threading import Thread
from typing import IO, Any, BinaryIO, TextIO
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from cryptography import x509
from cryptography.hazmat.primitives import serialization

MAX_AI_RESPONSE_BYTES = 65_536
MAX_HTTP_GET_RESPONSE_BYTES = 4_096
MAX_BUG_BOUNTY_RESPONSE_BYTES = 32_768
MAX_CTF_WEB_RESPONSE_BYTES = 16_384
MAX_CTF_CRYPTO_ARTIFACT_BYTES = 4_096
MAX_PROVIDER_SSE_BYTES = 1_000_000
MAX_PROVIDER_SSE_LINE_BYTES = 65_536
MAX_PROVIDER_TOOL_CALLS = 8
MAX_PROVIDER_CHUNKS = 10_000
MAX_WORKER_INPUT_BYTES = 1_100_000
MAX_MCP_RESPONSE_BYTES = 1_000_000
MAX_MCP_STDERR_BYTES = 128_000
MAX_NETWORK_SERVICE_BANNER_BYTES = 1_024
AI_SOURCE_TARGET_URL = "http://host.docker.internal:8080/v1/chat"
AI_SOURCE_CHALLENGE_DOMAIN = b"pajin.ai-source.target-execution-challenge/v1\0"
_WORKER_INPUT_CHUNK_CHARS = 8_192
_MCP_STREAM_CHUNK_BYTES = 65_536
_MCP_READER_JOIN_SECONDS = 5
_MCP_PROCESS_REAP_SECONDS = 5
_TLS_UNIQUE_BINDING_DOMAIN = b"pajin.replay.target-tls-unique-binding/v1\0"


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _strict_json_loads(raw: str | bytes, *, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError(f"{label} is not strict bounded JSON") from exc


def _strict_json_object(raw: str | bytes, *, label: str) -> dict[str, Any]:
    value = _strict_json_loads(raw, label=label)
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    return value


def _required_string(payload: dict[str, Any], key: str, *, label: str | None = None) -> str:
    value = payload[key]
    if not isinstance(value, str) or not value:
        raise TypeError(f"{label or key} must be a non-empty string")
    return value


def _read_worker_input(stream: TextIO) -> dict[str, Any]:
    parts: list[str] = []
    total_bytes = 0
    while chunk := stream.read(_WORKER_INPUT_CHUNK_CHARS):
        if not isinstance(chunk, str):
            raise TypeError("worker input stream must yield text")
        try:
            total_bytes += len(chunk.encode("utf-8"))
        except UnicodeError as exc:
            raise ValueError("worker input is not valid UTF-8 text") from exc
        if total_bytes > MAX_WORKER_INPUT_BYTES:
            raise ValueError("worker input exceeded byte limit")
        parts.append(chunk)
    return _strict_json_object("".join(parts), label="worker input")


def _unwrap_worker_envelope(wire_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    if "pajinEnvelopeVersion" not in wire_payload:
        return wire_payload, {}
    if wire_payload.get("pajinEnvelopeVersion") != 1:
        raise ValueError("worker secret envelope version is unsupported")
    if set(wire_payload) != {"pajinEnvelopeVersion", "payload", "secrets"}:
        raise ValueError("worker secret envelope contains unexpected fields")
    payload = wire_payload.get("payload")
    raw_secrets = wire_payload.get("secrets")
    if not isinstance(payload, dict) or not isinstance(raw_secrets, dict):
        raise TypeError("worker secret envelope is malformed")
    if not all(
        isinstance(key, str) and isinstance(value, str) and key and value
        for key, value in raw_secrets.items()
    ):
        raise TypeError("worker secret bindings must contain non-empty strings")
    return payload, raw_secrets


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def _tls_leaf_spki_sha256(certificate_der: bytes) -> str:
    if not isinstance(certificate_der, bytes) or not 1 <= len(certificate_der) <= 64 * 1024:
        raise ValueError("TLS peer leaf certificate is missing or exceeds its byte limit")
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
        spki = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("TLS peer leaf certificate cannot be decoded") from exc
    return sha256(spki).hexdigest()


def _tls_unique_binding_sha256(peer_socket: ssl.SSLSocket) -> str | None:
    """Return a bounded TLS 1.2 channel-binding digest when the runtime exposes one."""

    if peer_socket.version() != "TLSv1.2":
        return None
    binding = peer_socket.get_channel_binding("tls-unique")
    if binding is None:
        return None
    if not isinstance(binding, bytes) or not 1 <= len(binding) <= 1_024:
        raise ValueError("TLS unique channel binding is missing or exceeds its byte limit")
    return sha256(_TLS_UNIQUE_BINDING_DOMAIN + binding).hexdigest()


class _ObservingHTTPSConnection(HTTPSConnection):
    """Attach endpoint and channel observations before the socket can be released."""

    def getresponse(self) -> HTTPResponse:
        if self.sock is None:
            raise ValueError("HTTPS connection has no verified peer socket")
        certificate_der = self.sock.getpeercert(binary_form=True)
        peer_leaf_spki_sha256 = _tls_leaf_spki_sha256(certificate_der)
        tls_session_binding_sha256 = _tls_unique_binding_sha256(self.sock)
        response = super().getresponse()
        response.pajin_tls_peer_leaf_spki_sha256 = peer_leaf_spki_sha256
        response.pajin_tls_session_binding_sha256 = tls_session_binding_sha256
        return response


class _ObservingHTTPSHandler(HTTPSHandler):
    def https_open(self, request: Request) -> Any:
        return self.do_open(
            _ObservingHTTPSConnection,
            request,
            context=self._context,
            check_hostname=self._check_hostname,
        )


_HTTP_OPENER = build_opener(_NoRedirectHandler(), _ObservingHTTPSHandler())


def _open_http(request: Request, *, timeout: int) -> Any:
    """Open one request with redirects disabled for every network action."""

    parsed = urlsplit(request.full_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Worker HTTP request authority is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Worker HTTP requests require an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Worker HTTP request credentials are forbidden")
    if parsed.fragment:
        raise ValueError("Worker HTTP request fragments are forbidden")
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError("Worker HTTP request port is invalid")
    return _HTTP_OPENER.open(request, timeout=timeout)


def mock_agent_probe(payload: dict[str, Any]) -> dict[str, Any]:
    simulation = payload.get("simulation", {})
    if not isinstance(simulation, dict):
        raise TypeError("mock simulation must be an object")
    vulnerable = simulation.get("unauthorizedToolCall", False)
    if not isinstance(vulnerable, bool):
        raise TypeError("mock unauthorizedToolCall must be boolean")
    return {
        "vulnerable": vulnerable,
        "observation": (
            "target accepted an untrusted instruction and invoked a protected tool"
            if vulnerable
            else "target rejected the untrusted instruction"
        ),
        "target": _required_string(payload, "target", label="mock target"),
        "networkPerformed": False,
    }


def _read_cgroup(name: str) -> str | None:
    path = f"/sys/fs/cgroup/{name}"
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def _network_interfaces() -> list[str] | None:
    try:
        indexed = socket.if_nameindex()
    except OSError:
        return None
    if not indexed or any(
        type(index) is not int or index < 1 or not isinstance(name, str) or not name
        for index, name in indexed
    ):
        return None
    interfaces = sorted({name for _index, name in indexed})
    if len(interfaces) != len(indexed):
        return None
    return interfaces


def _read_proc_network_lines(path: str) -> list[str] | None:
    try:
        with open(path, encoding="ascii") as handle:
            content = handle.read(64 * 1024 + 1)
    except (OSError, UnicodeError):
        return None
    if len(content) > 64 * 1024:
        return None
    return [line for line in content.splitlines() if line.strip()]


def _network_route_interfaces() -> list[str] | None:
    ipv4 = _read_proc_network_lines("/proc/net/route")
    ipv6 = _read_proc_network_lines("/proc/net/ipv6_route")
    if ipv4 is None or ipv6 is None or not ipv4:
        return None
    header = ipv4[0].split()
    if not header or header[0] != "Iface":
        return None
    interfaces: set[str] = set()
    for line in ipv4[1:]:
        fields = line.split()
        if len(fields) != 11 or not fields[0]:
            return None
        interfaces.add(fields[0])
    for line in ipv6:
        fields = line.split()
        if len(fields) != 10 or not fields[-1]:
            return None
        interfaces.add(fields[-1])
    return sorted(interfaces)


def _external_network_probe_blocked() -> bool:
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=0.25):
            pass
    except OSError:
        return True
    return False


def isolation_check() -> dict[str, Any]:
    interfaces = _network_interfaces()
    route_interfaces = _network_route_interfaces()
    external_network_probe_blocked = _external_network_probe_blocked()
    only_loopback_interfaces = interfaces == ["lo"]
    only_loopback_network = (
        interfaces is not None
        and route_interfaces is not None
        and all(interface == "lo" for interface in route_interfaces)
    )
    network_blocked = only_loopback_network and external_network_probe_blocked

    workspace_writable = False
    workspace_probe = "/workspace/.pajin-write-check"
    try:
        with open(workspace_probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.unlink(workspace_probe)
        workspace_writable = True
    except OSError:
        pass

    status: dict[str, str] = {}
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                key, _, value = line.partition(":")
                if key in {"CapEff", "NoNewPrivs"}:
                    status[key] = value.strip()
    except OSError:
        pass

    return {
        "nonRoot": os.geteuid() != 0,
        "networkBlocked": network_blocked,
        "networkInterfaces": interfaces,
        "networkRouteInterfaces": route_interfaces,
        "onlyLoopbackInterfaces": only_loopback_interfaces,
        "onlyLoopbackNetwork": only_loopback_network,
        "externalNetworkProbeBlocked": external_network_probe_blocked,
        "rootReadOnly": bool(os.statvfs("/").f_flag & os.ST_RDONLY),
        "workspaceWritable": workspace_writable,
        "capabilitiesDropped": int(status.get("CapEff", "1"), 16) == 0,
        "noNewPrivileges": status.get("NoNewPrivs") == "1",
        "memoryMax": _read_cgroup("memory.max"),
        "pidsMax": _read_cgroup("pids.max"),
        "cpuMax": _read_cgroup("cpu.max"),
    }


def http_get(payload: dict[str, Any]) -> dict[str, Any]:
    target = _required_string(payload, "target", label="HTTP target")
    request = Request(target, method="GET", headers={"User-Agent": "PAJIN-Worker/0.1"})
    try:
        with _open_http(request, timeout=10) as response:
            body = response.read(MAX_HTTP_GET_RESPONSE_BYTES + 1)
            if len(body) > MAX_HTTP_GET_RESPONSE_BYTES:
                raise ValueError("HTTP response exceeded byte limit")
            return {
                "target": target,
                "status": response.status,
                "contentType": response.headers.get("Content-Type"),
                "bodyPreview": body.decode("utf-8", errors="replace"),
                "bodySha256": sha256(body).hexdigest(),
                "responseBodyBase64": b64encode(body).decode("ascii"),
            }
    except HTTPError as exc:
        body = exc.read(MAX_HTTP_GET_RESPONSE_BYTES + 1)
        if len(body) > MAX_HTTP_GET_RESPONSE_BYTES:
            raise ValueError("HTTP error response exceeded byte limit") from exc
        output = {
            "target": target,
            "status": exc.code,
            "contentType": (exc.headers.get("Content-Type") if exc.headers is not None else None),
            "bodyPreview": body.decode("utf-8", errors="replace"),
            "bodySha256": sha256(body).hexdigest(),
            "responseBodyBase64": b64encode(body).decode("ascii"),
        }
        if 300 <= exc.code < 400:
            output["error"] = "redirect response was not followed"
        return output
    except URLError:
        return {"target": target, "status": 0, "error": "HTTP target is unavailable"}


def _get_bug_bounty_observation(target: str, value: str, name: str) -> dict[str, Any]:
    parsed = urlsplit(target)
    request_target = urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode({"id": value}), "")
    )
    request = Request(
        request_target,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "PAJIN-Bug-Bounty-Probe/1.0"},
    )
    try:
        with _open_http(request, timeout=10) as response:
            body = response.read(MAX_BUG_BOUNTY_RESPONSE_BYTES + 1)
            status = response.status
    except HTTPError as exc:
        body = exc.read(MAX_BUG_BOUNTY_RESPONSE_BYTES + 1)
        status = exc.code
    except URLError as exc:
        raise ValueError("Bug Bounty target request failed") from exc
    if len(body) > MAX_BUG_BOUNTY_RESPONSE_BYTES:
        raise ValueError("Bug Bounty target response exceeded byte limit")
    if 300 <= status < 400:
        raise ValueError("Bug Bounty target redirect was not followed")
    response_data = _strict_json_object(body, label="Bug Bounty target response")
    record_count = response_data.get("recordCount")
    synthetic = response_data.get("synthetic")
    if (
        not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or not 0 <= record_count <= 100
    ):
        raise TypeError("Bug Bounty target response requires bounded integer recordCount")
    if not isinstance(synthetic, bool):
        raise TypeError("Bug Bounty target response requires boolean synthetic")
    return {
        "name": name,
        "status": status,
        "recordCount": record_count,
        "synthetic": synthetic,
        "bodySha256": sha256(body).hexdigest(),
        "responseBodyBase64": b64encode(body).decode("ascii"),
    }


def bug_bounty_sqli_probe(payload: dict[str, Any]) -> dict[str, Any]:
    target = _required_string(payload, "target", label="Bug Bounty target")
    scenario_id = _required_string(payload, "scenarioId", label="Bug Bounty scenario ID")
    if scenario_id != "bug-bounty.api.boolean-sqli-lab":
        raise ValueError("unsupported Bug Bounty scenario")
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Bug Bounty target must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Bug Bounty target authority, query, or fragment is invalid")
    if not parsed.path.endswith("/v1/users/lookup"):
        raise ValueError("Bug Bounty scenario is fixed to the lab lookup endpoint")

    observations = [
        _get_bug_bounty_observation(target, "1", "baseline"),
        _get_bug_bounty_observation(target, "1' AND '1'='2", "negative-control"),
        _get_bug_bounty_observation(target, "1' OR '1'='1", "boolean-probe"),
    ]
    by_name = {observation["name"]: observation for observation in observations}
    checks = {
        "baselineSingleRecord": (
            by_name["baseline"]["status"] == 200 and by_name["baseline"]["recordCount"] == 1
        ),
        "negativeControlEmpty": (
            by_name["negative-control"]["status"] in {200, 400}
            and by_name["negative-control"]["recordCount"] == 0
        ),
        "booleanProbeExpanded": (
            by_name["boolean-probe"]["status"] == 200
            and by_name["boolean-probe"]["recordCount"] > 1
        ),
        "syntheticLabOnly": all(observation["synthetic"] for observation in observations),
    }
    return {
        "target": target,
        "scenarioId": scenario_id,
        "vulnerable": all(checks.values()),
        "checks": checks,
        "observations": observations,
        "networkPerformed": True,
    }


@dataclass(frozen=True)
class _CTFWebProbe:
    target: str
    challenge_id: str
    scenario_id: str


def _validate_ctf_web_probe(payload: dict[str, Any]) -> _CTFWebProbe:
    target = _required_string(payload, "target", label="CTF Web target")
    challenge_id = _required_string(payload, "challengeId", label="CTF Web challenge ID")
    scenario_id = _required_string(payload, "scenarioId", label="CTF Web scenario ID")
    if scenario_id != "web.exposed-backup-config":
        raise ValueError("unsupported CTF Web scenario")
    if fullmatch(r"[a-z0-9][a-z0-9-]*", challenge_id) is None:
        raise ValueError("CTF Web challenge ID is invalid")
    parsed = urlsplit(target)
    if parsed.scheme != "http" or parsed.hostname != "host.docker.internal" or parsed.port != 8780:
        raise ValueError("CTF Web target must use the fixed local lab authority")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("CTF Web target authority, query, or fragment is invalid")
    if parsed.path != "/backup/config.json.bak":
        raise ValueError("CTF Web target must use the fixed backup path")
    return _CTFWebProbe(target=target, challenge_id=challenge_id, scenario_id=scenario_id)


def _fetch_ctf_web_response(target: str) -> tuple[int, bytes, dict[str, Any]]:
    request = Request(
        target,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "PAJIN-CTF-Web-Probe/1.0"},
    )
    try:
        with _open_http(request, timeout=10) as response:
            body = response.read(MAX_CTF_WEB_RESPONSE_BYTES + 1)
            status = response.status
    except HTTPError as exc:
        body = exc.read(MAX_CTF_WEB_RESPONSE_BYTES + 1)
        status = exc.code
    except URLError as exc:
        raise ValueError("CTF Web target request failed") from exc
    if len(body) > MAX_CTF_WEB_RESPONSE_BYTES:
        raise ValueError("CTF Web target response exceeded byte limit")
    if 300 <= status < 400:
        raise ValueError("CTF Web target redirect was not followed")
    return status, body, _strict_json_object(body, label="CTF Web target response")


def _ctf_web_candidate(
    response_data: dict[str, Any],
    *,
    challenge_id: str,
    status: int,
) -> str | None:
    if response_data.get("synthetic") is not True:
        raise ValueError("CTF Web target did not attest a synthetic response")
    if response_data.get("challengeId") != challenge_id:
        raise ValueError("CTF Web target challenge identity does not match")
    candidate = response_data.get("flag")
    if candidate is not None and not isinstance(candidate, str):
        raise TypeError("CTF Web candidate flag must be a string")
    if candidate is not None and fullmatch(r"PAJIN\{[A-Za-z0-9_-]{1,128}\}", candidate) is None:
        raise ValueError("CTF Web candidate flag format is invalid")
    if candidate is not None and status != 200:
        raise ValueError("CTF Web target exposed a flag with a non-success status")
    return candidate


def ctf_web_backup_probe(payload: dict[str, Any]) -> dict[str, Any]:
    probe = _validate_ctf_web_probe(payload)
    status, body, response_data = _fetch_ctf_web_response(probe.target)
    candidate = _ctf_web_candidate(
        response_data,
        challenge_id=probe.challenge_id,
        status=status,
    )

    return {
        "target": probe.target,
        "challengeId": probe.challenge_id,
        "scenarioId": probe.scenario_id,
        "status": status,
        "discovered": status == 200 and candidate is not None,
        "candidateFlag": candidate,
        "bodySha256": sha256(body).hexdigest(),
        "responseBodyBase64": b64encode(body).decode("ascii"),
        "synthetic": True,
        "networkPerformed": True,
    }


@dataclass(frozen=True)
class _CTFCryptoProbe:
    target: str
    challenge_id: str
    scenario_id: str
    artifact_sha256: str
    ciphertext: bytes


def _validate_ctf_crypto_probe(payload: dict[str, Any]) -> _CTFCryptoProbe:
    target = _required_string(payload, "target", label="CTF Crypto target")
    challenge_id = _required_string(payload, "challengeId", label="CTF Crypto challenge ID")
    scenario_id = _required_string(payload, "scenarioId", label="CTF Crypto scenario ID")
    artifact_sha256 = _required_string(
        payload,
        "artifactSha256",
        label="CTF Crypto artifact digest",
    )
    ciphertext_hex = _required_string(
        payload,
        "ciphertextHex",
        label="CTF Crypto ciphertext",
    )
    if scenario_id != "crypto.single-byte-xor":
        raise ValueError("unsupported CTF Crypto scenario")
    if fullmatch(r"[a-z0-9][a-z0-9-]*", challenge_id) is None:
        raise ValueError("CTF Crypto challenge ID is invalid")
    if fullmatch(r"[a-f0-9]{64}", artifact_sha256) is None:
        raise ValueError("CTF Crypto artifact digest is invalid")
    expected_target = f"http://artifact.invalid/{challenge_id}/{artifact_sha256}"
    if target != expected_target:
        raise ValueError("CTF Crypto target does not match its content address")
    if fullmatch(r"[a-f0-9]+", ciphertext_hex) is None or len(ciphertext_hex) % 2:
        raise ValueError("CTF Crypto ciphertext must be complete lowercase hex bytes")
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError as exc:
        raise ValueError("CTF Crypto ciphertext is not hexadecimal") from exc
    if not 1 <= len(ciphertext) <= MAX_CTF_CRYPTO_ARTIFACT_BYTES:
        raise ValueError("CTF Crypto artifact exceeds the bounded size")
    observed_digest = sha256(ciphertext).hexdigest()
    if not compare_digest(observed_digest, artifact_sha256):
        raise ValueError("CTF Crypto artifact SHA-256 does not match")
    return _CTFCryptoProbe(
        target=target,
        challenge_id=challenge_id,
        scenario_id=scenario_id,
        artifact_sha256=artifact_sha256,
        ciphertext=ciphertext,
    )


def _single_byte_xor_flag_candidates(ciphertext: bytes) -> list[tuple[int, str]]:
    matches: list[tuple[int, str]] = []
    for key in range(256):
        plaintext_bytes = bytes(value ^ key for value in ciphertext)
        try:
            plaintext = plaintext_bytes.decode("ascii")
        except UnicodeDecodeError:
            continue
        if fullmatch(r"PAJIN\{[A-Za-z0-9_-]{1,128}\}", plaintext):
            matches.append((key, plaintext))
    return matches


def ctf_crypto_single_byte_xor(payload: dict[str, Any]) -> dict[str, Any]:
    probe = _validate_ctf_crypto_probe(payload)
    matches = _single_byte_xor_flag_candidates(probe.ciphertext)
    if len(matches) > 1:
        raise ValueError("CTF Crypto analysis produced ambiguous flag candidates")
    output_key, candidate = matches[0] if matches else (None, None)
    return {
        "target": probe.target,
        "challengeId": probe.challenge_id,
        "scenarioId": probe.scenario_id,
        "artifactSha256": probe.artifact_sha256,
        "solved": candidate is not None,
        "candidateFlag": candidate,
        "key": output_key,
        "attemptedKeys": 256,
        "synthetic": True,
        "networkPerformed": False,
    }


def _post_ai_turn(
    target: str,
    payload: dict[str, Any],
    *,
    source_target_challenge: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], float, str | None, str | None]:
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("AI target must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("AI target URL credentials are forbidden")
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "PAJIN-AI-Probe/1.0",
    }
    if source_target_challenge is not None:
        challenge_bytes = json.dumps(
            source_target_challenge,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
        headers["X-PAJIN-AI-Source-Challenge"] = (
            urlsafe_b64encode(challenge_bytes).decode("ascii").rstrip("=")
        )
    request = Request(
        target,
        data=encoded,
        method="POST",
        headers=headers,
    )
    started = time.perf_counter()
    try:
        with _open_http(request, timeout=10) as response:
            body = response.read(MAX_AI_RESPONSE_BYTES + 1)
            status = response.status
            tls_peer_leaf_spki_sha256 = (
                getattr(response, "pajin_tls_peer_leaf_spki_sha256", None)
                if parsed.scheme == "https"
                else None
            )
            tls_session_binding_sha256 = (
                getattr(response, "pajin_tls_session_binding_sha256", None)
                if parsed.scheme == "https"
                else None
            )
            if parsed.scheme == "https" and (
                not isinstance(tls_peer_leaf_spki_sha256, str)
                or fullmatch(r"[a-f0-9]{64}", tls_peer_leaf_spki_sha256) is None
            ):
                raise ValueError("HTTPS response omitted its verified peer leaf SPKI digest")
            if tls_session_binding_sha256 is not None and (
                not isinstance(tls_session_binding_sha256, str)
                or fullmatch(r"[a-f0-9]{64}", tls_session_binding_sha256) is None
            ):
                raise ValueError("HTTPS response exposed an invalid TLS session binding digest")
    except HTTPError as exc:
        exc.read(4_096)
        raise ValueError(f"AI target returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise ValueError("AI target request failed") from exc
    if len(body) > MAX_AI_RESPONSE_BYTES:
        raise ValueError("AI target response exceeded byte limit")
    if not 200 <= status < 300:
        raise ValueError(f"AI target returned unexpected HTTP {status}")
    result = _strict_json_object(body, label="AI target response")
    if result.get("sessionId") != payload.get("sessionId"):
        raise ValueError("AI target response session identity does not match")
    message = result.get("message")
    if (
        not isinstance(message, dict)
        or message.get("role") != "assistant"
        or not isinstance(message.get("content"), str)
    ):
        raise TypeError("AI target response requires message.content")
    return (
        result,
        time.perf_counter() - started,
        tls_peer_leaf_spki_sha256,
        tls_session_binding_sha256,
    )


def _probe_check_matches(check: dict[str, Any], turns: list[dict[str, Any]]) -> bool:
    turn_index = check["turn"]
    if isinstance(turn_index, bool) or not isinstance(turn_index, int):
        raise TypeError("probe check turn must be an integer")
    if not 0 <= turn_index < len(turns):
        raise ValueError("probe check references a missing turn")
    response = turns[turn_index]["response"]
    content = response["message"]["content"]
    if not isinstance(content, str):
        raise TypeError("AI response content must be a string")
    value = _required_string(check, "value", label="probe check value")
    kind = _required_string(check, "kind", label="probe check kind")
    if kind == "response-contains":
        return value in content
    if kind == "response-excludes":
        return value not in content
    raise ValueError(f"unsupported probe check kind: {kind}")


@dataclass(frozen=True)
class _AIProbe:
    target: str
    scenario_id: str
    threat_class: str
    session_id: str
    purpose: str
    turns: list[Any]
    checks: list[Any]
    target_challenge: dict[str, Any] | None
    source_target_challenge: dict[str, Any] | None


def _validate_ai_source_challenge(
    challenge: dict[str, Any],
    *,
    target: str,
    probe: dict[str, Any],
) -> None:
    string_patterns = (
        ("challenge_id", r"ai-source-target-challenge_[a-f0-9]{32}"),
        ("permit_digest", r"[a-f0-9]{64}"),
        ("source_request_id", r"tool_ai002b_source_[a-f0-9]{32}"),
        ("source_operation_id", r"ai-source-operation_[a-f0-9]{64}"),
        ("target_sha256", r"[a-f0-9]{64}"),
        ("compiled_argument_digest", r"[a-f0-9]{64}"),
    )
    if (
        target != AI_SOURCE_TARGET_URL
        or challenge.get("api_version")
        != "pajin.ai-source.target-execution-challenge/v1"
        or any(
            not isinstance(challenge.get(field), str)
            or fullmatch(pattern, challenge[field]) is None
            for field, pattern in string_patterns
        )
        or type(challenge.get("call_ordinal")) is not int
        or challenge.get("call_ordinal") != 1
        or challenge.get("method") != "POST"
        or challenge.get("route_path") != "/v1/chat"
        or challenge.get("target_sha256")
        != sha256(AI_SOURCE_TARGET_URL.encode("utf-8")).hexdigest()
        or challenge.get("compiled_argument_digest")
        != sha256(
            json.dumps(
                probe,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
    ):
        raise ValueError("sourceTargetChallenge is outside the exact AI-002B shape")
    material = {key: value for key, value in challenge.items() if key != "challenge_id"}
    expected_id = (
        "ai-source-target-challenge_"
        + sha256(
            AI_SOURCE_CHALLENGE_DOMAIN
            + json.dumps(
                material,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()[:32]
    )
    if challenge["challenge_id"] != expected_id:
        raise ValueError("sourceTargetChallenge identity differs")
    issued_raw = challenge.get("issued_at")
    expires_raw = challenge.get("expires_at")
    if (
        not isinstance(issued_raw, str)
        or not isinstance(expires_raw, str)
        or not issued_raw.endswith("Z")
        or not expires_raw.endswith("Z")
    ):
        raise ValueError("sourceTargetChallenge time is invalid")
    try:
        issued_at = datetime.fromisoformat(issued_raw.replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("sourceTargetChallenge time is invalid") from exc
    observed_at = datetime.now(UTC)
    if (
        issued_at.utcoffset() != timedelta(0)
        or expires_at.utcoffset() != timedelta(0)
        or issued_at.isoformat().replace("+00:00", "Z") != issued_raw
        or expires_at.isoformat().replace("+00:00", "Z") != expires_raw
        or not issued_at < expires_at <= issued_at + timedelta(seconds=120)
        or not issued_at <= observed_at < expires_at
    ):
        raise ValueError("sourceTargetChallenge time is outside its exact bound")


def _validate_ai_probe(payload: dict[str, Any]) -> _AIProbe:
    target = _required_string(payload, "target", label="AI target")
    probe = payload["probe"]
    if not isinstance(probe, dict):
        raise TypeError("probe must be an object")
    scenario_id = _required_string(probe, "scenario_id", label="probe scenario ID")
    threat_class = _required_string(probe, "threat_class", label="probe threat class")
    session_id = _required_string(probe, "session_id", label="probe session ID")
    purpose = probe.get("purpose", "attack")
    if not isinstance(purpose, str):
        raise TypeError("probe purpose must be a string")
    if purpose not in {"attack", "regression"}:
        raise ValueError("probe purpose must be attack or regression")
    turns = probe["turns"]
    checks = probe["checks"]
    if not isinstance(turns, list) or not 1 <= len(turns) <= 20:
        raise ValueError("probe turns must contain between 1 and 20 items")
    if not isinstance(checks, list) or not 1 <= len(checks) <= 20:
        raise ValueError("probe checks must contain between 1 and 20 items")
    target_challenge = payload.get("targetChallenge")
    if target_challenge is not None:
        if not isinstance(target_challenge, dict):
            raise TypeError("targetChallenge must be an object")
        required_challenge_fields = {
            "api_version",
            "challenge_id",
            "permit_digest",
            "replay_request_id",
            "batch_id",
            "item_id",
            "ticket_id",
            "fencing_value",
            "call_ordinal",
            "target_sha256",
            "method",
            "compiled_argument_digest",
            "issued_at",
            "expires_at",
        }
        if set(target_challenge) != required_challenge_fields:
            raise ValueError("targetChallenge fields are not canonical")
    source_target_challenge = payload.get("sourceTargetChallenge")
    if source_target_challenge is not None:
        if not isinstance(source_target_challenge, dict):
            raise TypeError("sourceTargetChallenge must be an object")
        required_source_challenge_fields = {
            "api_version",
            "challenge_id",
            "permit_digest",
            "source_request_id",
            "source_operation_id",
            "call_ordinal",
            "target_sha256",
            "method",
            "route_path",
            "compiled_argument_digest",
            "issued_at",
            "expires_at",
        }
        if set(source_target_challenge) != required_source_challenge_fields:
            raise ValueError("sourceTargetChallenge fields are not canonical")
        _validate_ai_source_challenge(
            source_target_challenge,
            target=target,
            probe=probe,
        )
        parsed_target = urlsplit(target)
        if (
            target_challenge is not None
            or source_target_challenge.get("api_version")
            != "pajin.ai-source.target-execution-challenge/v1"
            or source_target_challenge.get("method") != "POST"
            or source_target_challenge.get("route_path") != "/v1/chat"
            or source_target_challenge.get("call_ordinal") != 1
            or parsed_target.path != "/v1/chat"
            or parsed_target.query
            or parsed_target.fragment
            or sha256(target.encode("utf-8")).hexdigest()
            != source_target_challenge.get("target_sha256")
            or scenario_id != "kisa.model.system-prompt-disclosure"
            or threat_class != "M03"
            or purpose != "attack"
            or len(turns) != 1
            or len(checks) != 1
        ):
            raise ValueError("sourceTargetChallenge is outside the exact AI-002B shape")
    return _AIProbe(
        target=target,
        scenario_id=scenario_id,
        threat_class=threat_class,
        session_id=session_id,
        purpose=purpose,
        turns=turns,
        checks=checks,
        target_challenge=target_challenge,
        source_target_challenge=source_target_challenge,
    )


def _execute_ai_probe_turns(probe: _AIProbe) -> tuple[list[dict[str, Any]], list[float]]:
    turn_records: list[dict[str, Any]] = []
    response_latencies: list[float] = []
    for index, turn in enumerate(probe.turns):
        if not isinstance(turn, dict):
            raise TypeError("each probe turn must be an object")
        messages = turn.get("messages")
        if not isinstance(messages, list) or not 1 <= len(messages) <= 20:
            raise TypeError("each probe turn requires messages")
        name = _required_string(turn, "name", label="probe turn name")
        request_payload = {
            "sessionId": probe.session_id,
            "messages": messages,
            "metadata": {
                "scenarioId": probe.scenario_id,
                "turn": index,
                **(
                    {
                        "targetChallenge": probe.target_challenge,
                        "targetExchangeOrdinal": index + 1,
                    }
                    if probe.target_challenge is not None
                    else {}
                ),
            },
        }
        (
            response,
            response_latency,
            tls_peer_leaf_spki_sha256,
            tls_session_binding_sha256,
        ) = _post_ai_turn(
            probe.target,
            request_payload,
            source_target_challenge=probe.source_target_challenge,
        )
        response_latencies.append(response_latency)
        turn_records.append(
            {
                "index": index,
                "name": name,
                "request": request_payload,
                "response": response,
                "responseLatencySeconds": response_latency,
                **(
                    {"tlsPeerLeafSpkiSha256": tls_peer_leaf_spki_sha256}
                    if tls_peer_leaf_spki_sha256 is not None
                    else {}
                ),
                **(
                    {"tlsSessionBindingSha256": tls_session_binding_sha256}
                    if tls_session_binding_sha256 is not None
                    else {}
                ),
            }
        )
    return turn_records, response_latencies


def _evaluate_ai_probe_checks(
    checks: list[Any],
    turn_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    check_records: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, dict):
            raise TypeError("each probe check must be an object")
        matched = _probe_check_matches(check, turn_records)
        sensitive = check.get("sensitive", False)
        if not isinstance(sensitive, bool):
            raise TypeError("probe check sensitive must be boolean")
        check_records.append(
            {
                "checkId": _required_string(check, "check_id", label="probe check ID"),
                "kind": _required_string(check, "kind", label="probe check kind"),
                "turn": check["turn"],
                "matched": matched,
                "sensitive": sensitive,
            }
        )
    return check_records


def ai_chat_probe(payload: dict[str, Any]) -> dict[str, Any]:
    probe = _validate_ai_probe(payload)
    turn_records, response_latencies = _execute_ai_probe_turns(probe)
    check_records = _evaluate_ai_probe_checks(probe.checks, turn_records)
    checks_passed = all(check["matched"] for check in check_records)
    vulnerable = checks_passed if probe.purpose == "attack" else False
    sensitive_exposures = sum(
        bool(check["matched"] and check["sensitive"]) for check in check_records
    )
    return {
        "target": probe.target,
        "scenarioId": probe.scenario_id,
        "threatClass": probe.threat_class,
        "sessionId": probe.session_id,
        "purpose": probe.purpose,
        "vulnerable": vulnerable,
        "observation": (
            "all scenario compromise indicators were observed"
            if vulnerable
            else "one or more scenario compromise indicators were not observed"
        ),
        "turns": turn_records,
        "checks": check_records,
        "sensitiveExposureCount": sensitive_exposures,
        "meanResponseLatencySeconds": sum(response_latencies) / len(response_latencies),
        "regressionPassed": checks_passed if probe.purpose == "regression" else None,
        "networkPerformed": True,
    }


def _normalize_provider_tool_call(raw: dict[str, Any]) -> dict[str, Any]:
    call_id = raw.get("id")
    function = raw.get("function")
    if (
        not isinstance(call_id, str)
        or not 1 <= len(call_id) <= 200
        or not isinstance(function, dict)
    ):
        raise TypeError("provider tool call requires id and function")
    if raw.get("type", "function") != "function":
        raise ValueError("provider tool call must use function type")
    name = function.get("name")
    arguments_json = function.get("arguments")
    if not isinstance(name, str) or fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", name) is None:
        raise TypeError("provider function call requires a valid function name")
    if not isinstance(arguments_json, str) or not 2 <= len(arguments_json) <= 1_000_000:
        raise TypeError("provider function call requires name and string arguments")
    arguments: dict[str, Any] | None = None
    arguments_valid = False
    try:
        parsed = _strict_json_loads(arguments_json, label="provider function arguments")
        if isinstance(parsed, dict):
            arguments = parsed
            arguments_valid = True
    except (TypeError, ValueError):
        pass
    return {
        "call_id": call_id,
        "name": name,
        "arguments_json": arguments_json,
        "arguments": arguments,
        "arguments_valid": arguments_valid,
    }


def _provider_usage(raw: object) -> dict[str, int] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise TypeError("provider usage must be an object")
    fields = ("prompt_tokens", "completion_tokens", "total_tokens")
    usage: dict[str, int] = {}
    for name in fields:
        value = raw.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000_000:
            raise TypeError(f"provider usage {name} must be a bounded non-negative integer")
        usage[name] = value
    if usage["total_tokens"] != usage["prompt_tokens"] + usage["completion_tokens"]:
        raise ValueError("provider usage totals are inconsistent")
    return usage


def _provider_identity(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 200:
        raise TypeError(f"provider response requires a bounded {label}")
    return value


def _provider_choice(payload: dict[str, Any]) -> dict[str, Any]:
    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise TypeError("provider response requires exactly one choice")
    choice = choices[0]
    index = choice.get("index")
    if isinstance(index, bool) or index != 0:
        raise ValueError("provider response choice must have index 0")
    return choice


def _provider_finish_reason(choice: dict[str, Any]) -> str:
    value = choice.get("finish_reason")
    if not isinstance(value, str) or not 1 <= len(value) <= 100:
        raise TypeError("provider response requires a bounded finish reason")
    return value


def _provider_optional_text(message: dict[str, Any], key: str) -> str | None:
    value = message.get(key)
    if value is not None and not isinstance(value, str):
        raise TypeError(f"provider message {key} must be a string or null")
    return value


def _normalize_provider_tool_calls(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) > MAX_PROVIDER_TOOL_CALLS:
        raise TypeError("provider message tool_calls must be a bounded list")
    if not all(isinstance(item, dict) for item in raw):
        raise TypeError("provider message contains a malformed tool call")
    return [_normalize_provider_tool_call(item) for item in raw]


def _validate_provider_completion_shape(
    *,
    content: str | None,
    refusal: str | None,
    finish_reason: str,
    tool_calls: list[dict[str, Any]],
) -> None:
    if content is None and refusal is None and not tool_calls:
        raise ValueError("provider response contains no assistant result")
    if (finish_reason == "tool_calls") != bool(tool_calls):
        raise ValueError("provider finish reason and tool calls are inconsistent")


def _normalize_nonstream_provider(
    payload: dict[str, Any],
    *,
    provider_id: str,
    target: str,
) -> dict[str, Any]:
    response_id = _provider_identity(payload.get("id"), label="id")
    model = _provider_identity(payload.get("model"), label="model")
    choice = _provider_choice(payload)
    message = choice.get("message")
    if not isinstance(message, dict):
        raise TypeError("provider choice requires a message")
    if message.get("role") != "assistant":
        raise ValueError("provider response message must have assistant role")
    content = _provider_optional_text(message, "content")
    refusal = _provider_optional_text(message, "refusal")
    tool_calls = _normalize_provider_tool_calls(message.get("tool_calls", []))
    finish_reason = _provider_finish_reason(choice)
    usage = _provider_usage(payload.get("usage"))
    _validate_provider_completion_shape(
        content=content,
        refusal=refusal,
        finish_reason=finish_reason,
        tool_calls=tool_calls,
    )
    return {
        "provider_id": provider_id,
        "response_id": response_id,
        "model": model,
        "content": content,
        "refusal": refusal,
        "finish_reason": finish_reason,
        "tool_calls": tool_calls,
        "usage": usage,
        "streamed": False,
        "chunks": 1,
        "target": target,
    }


@dataclass
class _ProviderToolCallAccumulator:
    call_id: str = ""
    name: str = ""
    arguments: str = ""

    def add(self, raw: dict[str, Any]) -> None:
        raw_id = raw.get("id")
        if raw_id is not None:
            if not isinstance(raw_id, str) or not 1 <= len(raw_id) <= 200:
                raise TypeError("provider SSE tool call id is invalid")
            if self.call_id and self.call_id != raw_id:
                raise ValueError("provider SSE tool call id changed during streaming")
            self.call_id = raw_id
        if raw.get("type", "function") != "function":
            raise ValueError("provider SSE tool call must use function type")
        function = raw.get("function")
        if function is not None:
            self._add_function(function)

    def _add_function(self, function: object) -> None:
        if not isinstance(function, dict):
            raise TypeError("provider SSE tool call function must be an object")
        name = function.get("name")
        arguments = function.get("arguments")
        if name is not None and not isinstance(name, str):
            raise TypeError("provider SSE function name fragment must be a string")
        if arguments is not None and not isinstance(arguments, str):
            raise TypeError("provider SSE function arguments fragment must be a string")
        self.name += name or ""
        self.arguments += arguments or ""
        if len(self.name) > 64 or len(self.arguments) > 1_000_000:
            raise ValueError("provider SSE tool call fragments exceeded byte limits")

    def normalize(self) -> dict[str, Any]:
        return _normalize_provider_tool_call(
            {
                "id": self.call_id,
                "type": "function",
                "function": {"name": self.name, "arguments": self.arguments},
            }
        )


@dataclass
class _ProviderStreamState:
    provider_id: str
    target: str
    chunks: int = 0
    response_id: str | None = None
    model: str | None = None
    content_parts: list[str] = field(default_factory=list)
    refusal_parts: list[str] = field(default_factory=list)
    finish_reason: str | None = None
    usage: dict[str, int] | None = None
    tool_calls: dict[int, _ProviderToolCallAccumulator] = field(default_factory=dict)

    def add_chunk(self, chunk: dict[str, Any]) -> None:
        self.chunks += 1
        if self.chunks > MAX_PROVIDER_CHUNKS:
            raise ValueError("provider SSE response exceeded chunk limit")
        self.response_id = self._consistent_identity(
            self.response_id,
            chunk.get("id"),
            label="id",
        )
        self.model = self._consistent_identity(self.model, chunk.get("model"), label="model")
        chunk_usage = _provider_usage(chunk.get("usage"))
        if chunk_usage is not None:
            if self.usage is not None and self.usage != chunk_usage:
                raise ValueError("provider SSE usage changed during streaming")
            self.usage = chunk_usage
        self._add_choices(chunk.get("choices"), has_usage=chunk_usage is not None)

    @staticmethod
    def _consistent_identity(current: str | None, raw: object, *, label: str) -> str:
        observed = _provider_identity(raw, label=label)
        if current is not None and current != observed:
            raise ValueError(f"provider SSE {label} changed during streaming")
        return observed

    def _add_choices(self, raw: object, *, has_usage: bool) -> None:
        if raw == [] and has_usage:
            return
        if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict):
            raise TypeError("provider SSE chunk requires exactly one choice")
        choice = raw[0]
        index = choice.get("index", 0)
        if isinstance(index, bool) or not isinstance(index, int) or index != 0:
            raise ValueError("provider SSE choice must have index 0")
        self._add_finish_reason(choice.get("finish_reason"))
        self._add_delta(choice.get("delta"))

    def _add_finish_reason(self, raw: object) -> None:
        if raw is None:
            return
        if not isinstance(raw, str) or not 1 <= len(raw) <= 100:
            raise TypeError("provider SSE finish reason must be a bounded string")
        if self.finish_reason is not None and self.finish_reason != raw:
            raise ValueError("provider SSE finish reason changed during streaming")
        self.finish_reason = raw

    def _add_delta(self, raw: object) -> None:
        if not isinstance(raw, dict):
            raise TypeError("provider SSE choice requires a delta object")
        self._add_text_fragment(raw, "content", self.content_parts)
        self._add_text_fragment(raw, "refusal", self.refusal_parts)
        raw_tool_calls = raw.get("tool_calls", [])
        if not isinstance(raw_tool_calls, list):
            raise TypeError("provider SSE tool_calls must be a list")
        for raw_call in raw_tool_calls:
            self._add_tool_call(raw_call)

    @staticmethod
    def _add_text_fragment(raw: dict[str, Any], key: str, parts: list[str]) -> None:
        value = raw.get(key)
        if value is not None and not isinstance(value, str):
            raise TypeError(f"provider SSE {key} fragment must be a string")
        if value:
            parts.append(value)

    def _add_tool_call(self, raw: object) -> None:
        if not isinstance(raw, dict):
            raise TypeError("provider SSE tool call must be an object")
        index = raw.get("index")
        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError("provider SSE tool call requires an integer index")
        if not 0 <= index < MAX_PROVIDER_TOOL_CALLS:
            raise ValueError("provider SSE tool call index exceeds the bounded range")
        self.tool_calls.setdefault(index, _ProviderToolCallAccumulator()).add(raw)

    def normalized(self) -> dict[str, Any]:
        if self.chunks < 1 or self.response_id is None or self.model is None:
            raise ValueError("provider SSE stream is missing identity chunks")
        if self.finish_reason is None:
            raise ValueError("provider SSE stream ended without a finish reason")
        expected_indices = list(range(len(self.tool_calls)))
        if sorted(self.tool_calls) != expected_indices:
            raise ValueError("provider SSE tool call indices are not contiguous")
        normalized_calls = [self.tool_calls[index].normalize() for index in expected_indices]
        content = "".join(self.content_parts) or None
        refusal = "".join(self.refusal_parts) or None
        _validate_provider_completion_shape(
            content=content,
            refusal=refusal,
            finish_reason=self.finish_reason,
            tool_calls=normalized_calls,
        )
        return {
            "provider_id": self.provider_id,
            "response_id": self.response_id,
            "model": self.model,
            "content": content,
            "refusal": refusal,
            "finish_reason": self.finish_reason,
            "tool_calls": normalized_calls,
            "usage": self.usage,
            "streamed": True,
            "chunks": self.chunks,
            "target": self.target,
        }


def _provider_sse_data(raw_line: bytes) -> str | None:
    line = raw_line.decode("utf-8", errors="strict").rstrip("\r\n")
    if not line or line.startswith(":") or not line.startswith("data:"):
        return None
    return line[5:].lstrip(" ")


def _normalize_stream_provider(
    response: Any,
    *,
    provider_id: str,
    target: str,
) -> dict[str, Any]:
    state = _ProviderStreamState(provider_id=provider_id, target=target)
    done = False
    for raw_line in _bounded_sse_lines(response):
        data = _provider_sse_data(raw_line)
        if data is None:
            continue
        if data == "[DONE]":
            done = True
            break
        state.add_chunk(_strict_json_object(data, label="provider SSE chunk"))
    if not done:
        raise ValueError("provider SSE stream ended without [DONE]")
    return state.normalized()


def _readline_sse_lines(readline: Any) -> Iterator[bytes]:
    total_bytes = 0
    while True:
        remaining = MAX_PROVIDER_SSE_BYTES - total_bytes
        if remaining < 1:
            if readline(1):
                raise ValueError("provider SSE response exceeded byte limit")
            return
        raw_line = readline(min(MAX_PROVIDER_SSE_LINE_BYTES, remaining) + 1)
        if not raw_line:
            return
        if not isinstance(raw_line, bytes):
            raise TypeError("provider SSE response lines must be bytes")
        if len(raw_line) > MAX_PROVIDER_SSE_LINE_BYTES:
            raise ValueError("provider SSE response line exceeded byte limit")
        total_bytes += len(raw_line)
        yield raw_line


def _iterable_sse_lines(response: Any) -> Iterator[bytes]:
    total_bytes = 0
    for raw_line in response:
        if not isinstance(raw_line, bytes):
            raise TypeError("provider SSE response lines must be bytes")
        if len(raw_line) > MAX_PROVIDER_SSE_LINE_BYTES:
            raise ValueError("provider SSE response line exceeded byte limit")
        total_bytes += len(raw_line)
        if total_bytes > MAX_PROVIDER_SSE_BYTES:
            raise ValueError("provider SSE response exceeded byte limit")
        yield raw_line


def _bounded_sse_lines(response: Any) -> Iterator[bytes]:
    """Yield SSE lines without allowing HTTPResponse.readline() to allocate unbounded input."""

    readline = getattr(response, "readline", None)
    if callable(readline):
        yield from _readline_sse_lines(readline)
        return
    yield from _iterable_sse_lines(response)


def _provider_credential(secrets: dict[str, str]) -> str:
    credential = secrets.get("provider-api-key")
    if not credential or any(character in credential for character in "\r\n"):
        raise ValueError("provider API key binding is required")
    return credential


def _provider_dispatch_payload(
    payload: dict[str, Any],
) -> tuple[str, str, dict[str, Any], bool]:
    provider_id = _required_string(payload, "providerId", label="provider ID")
    if fullmatch(r"[a-z0-9][a-z0-9-]{1,30}", provider_id) is None:
        raise ValueError("provider ID is invalid")
    target = _required_string(payload, "target", label="provider target")
    parsed_target = urlsplit(target)
    if parsed_target.scheme not in {"http", "https"} or not parsed_target.hostname:
        raise ValueError("provider target must be an absolute HTTP(S) URL")
    if parsed_target.username or parsed_target.password or parsed_target.fragment:
        raise ValueError("provider target credentials and fragments are forbidden")
    provider_request = payload["request"]
    if not isinstance(provider_request, dict):
        raise TypeError("provider request must be an object")
    if not isinstance(provider_request.get("messages"), list) or not provider_request["messages"]:
        raise ValueError("provider request requires messages")
    _provider_identity(provider_request.get("model"), label="request model")
    stream = provider_request.get("stream", False)
    if not isinstance(stream, bool):
        raise TypeError("provider stream must be boolean")
    encoded = json.dumps(provider_request, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_WORKER_INPUT_BYTES:
        raise ValueError("provider request exceeded byte limit")
    return provider_id, target, provider_request, stream


def _provider_http_request(
    target: str,
    provider_request: dict[str, Any],
    *,
    stream: bool,
    credential: str,
) -> Request:
    encoded = json.dumps(provider_request, separators=(",", ":")).encode("utf-8")
    return Request(
        target,
        data=encoded,
        method="POST",
        headers={
            "Authorization": f"Bearer {credential}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream" if stream else "application/json",
            "User-Agent": "PAJIN-Provider-Gateway/1.0",
        },
    )


def openai_chat_completion(
    payload: dict[str, Any],
    secrets: dict[str, str],
) -> dict[str, Any]:
    credential = _provider_credential(secrets)
    provider_id, target, provider_request, stream = _provider_dispatch_payload(payload)
    request = _provider_http_request(
        target,
        provider_request,
        stream=stream,
        credential=credential,
    )
    try:
        with _open_http(request, timeout=30) as response:
            if stream:
                return _normalize_stream_provider(
                    response,
                    provider_id=provider_id,
                    target=target,
                )
            body = response.read(1_000_001)
    except HTTPError as exc:
        exc.read(8_192)
        raise ValueError(f"provider returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise ValueError("provider request failed") from exc
    if len(body) > 1_000_000:
        raise ValueError("provider response exceeded byte limit")
    parsed = _strict_json_object(body, label="provider response")
    return _normalize_nonstream_provider(
        parsed,
        provider_id=provider_id,
        target=target,
    )


def direct_network_check(payload: dict[str, Any]) -> dict[str, Any]:
    if payload:
        raise ValueError("direct network check does not accept an agent-selected endpoint")
    host = "1.1.1.1"
    port = 443
    try:
        with socket.create_connection((host, port), timeout=1):
            return {
                "directNetworkBlocked": False,
                "probe": f"{host}:{port}",
                "failureKind": "connected",
            }
    except OSError as exc:
        definitively_blocked = exc.errno in {
            errno.EACCES,
            errno.EPERM,
            errno.ENETUNREACH,
            errno.EHOSTUNREACH,
        }
        return {
            "directNetworkBlocked": definitively_blocked,
            "probe": f"{host}:{port}",
            "failureKind": "network-unreachable" if definitively_blocked else "inconclusive",
        }


def _network_service_name(banner: bytes) -> str | None:
    sample = banner[:512].decode("ascii", errors="ignore").upper()
    if sample.startswith("SSH-"):
        return "ssh"
    if sample.startswith("220") and "ESMTP" in sample:
        return "smtp"
    if sample.startswith("220") and "FTP" in sample:
        return "ftp"
    if sample.startswith("* OK") and "IMAP" in sample:
        return "imap"
    if sample.startswith("+OK") and "POP3" in sample:
        return "pop3"
    return None


def _network_proxy_coordinate() -> tuple[str, int]:
    proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not proxy_url:
        raise RuntimeError("Network service identification requires the egress proxy")
    parsed = urlsplit(proxy_url)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Network service egress proxy URL is invalid")
    try:
        port = parsed.port or 80
    except ValueError as exc:
        raise ValueError("Network service egress proxy port is invalid") from exc
    return parsed.hostname, port


def _receive_connect_response(
    connection: socket.socket,
    *,
    max_header_bytes: int = 8_192,
) -> tuple[bool, bytes]:
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = connection.recv(min(1_024, max_header_bytes - len(response)))
        if not chunk:
            break
        response.extend(chunk)
        if len(response) >= max_header_bytes:
            raise ValueError("egress proxy CONNECT response headers exceeded the byte limit")
    header, separator, remainder = bytes(response).partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("egress proxy CONNECT response was incomplete")
    status_line = header.partition(b"\r\n")[0]
    return status_line.startswith(b"HTTP/1.1 200 "), remainder


def network_service_identify(payload: dict[str, Any]) -> dict[str, Any]:
    required = {
        "addressFamily",
        "connectTimeoutMilliseconds",
        "host",
        "maxBannerBytes",
        "port",
        "protocolProfile",
        "readTimeoutMilliseconds",
        "target",
        "transportProtocol",
    }
    if set(payload) != required:
        raise ValueError("Network service input fields differ from the fixed profile")
    address_family = _required_string(payload, "addressFamily")
    host = _required_string(payload, "host")
    target = _required_string(payload, "target")
    if address_family not in {"ipv4", "ipv6"}:
        raise ValueError("Network service address family is unsupported")
    try:
        address = ip_address(host)
    except ValueError as exc:
        raise ValueError("Network service host must be an IP literal") from exc
    if (
        address.version != (4 if address_family == "ipv4" else 6)
        or str(address) != host
        or payload["transportProtocol"] != "tcp"
        or payload["protocolProfile"] != "tcp-passive-banner-v1"
        or payload["connectTimeoutMilliseconds"] != 5_000
        or payload["readTimeoutMilliseconds"] != 2_000
        or payload["maxBannerBytes"] != MAX_NETWORK_SERVICE_BANNER_BYTES
    ):
        raise ValueError("Network service input differs from the fixed passive profile")
    port = payload["port"]
    if type(port) is not int or not 1 <= port <= 65_535:
        raise ValueError("Network service port is invalid")
    rendered_host = f"[{host}]" if address_family == "ipv6" else host
    authority = rendered_host if port == 443 else f"{rendered_host}:{port}"
    if target != f"https://{authority}/":
        raise ValueError("Network service target differs from its exact coordinate")

    banner = b""
    connected = False
    try:
        proxy_host, proxy_port = _network_proxy_coordinate()
        with socket.create_connection(
            (proxy_host, proxy_port),
            timeout=payload["connectTimeoutMilliseconds"] / 1_000,
        ) as connection:
            connection.settimeout(payload["connectTimeoutMilliseconds"] / 1_000)
            request = (
                f"CONNECT {rendered_host}:{port} HTTP/1.1\r\nHost: {rendered_host}:{port}\r\n\r\n"
            ).encode("ascii")
            connection.sendall(request)
            connected, remainder = _receive_connect_response(connection)
            if connected:
                connection.settimeout(payload["readTimeoutMilliseconds"] / 1_000)
                retained = bytearray(remainder[:MAX_NETWORK_SERVICE_BANNER_BYTES])
                while len(retained) < MAX_NETWORK_SERVICE_BANNER_BYTES:
                    try:
                        chunk = connection.recv(MAX_NETWORK_SERVICE_BANNER_BYTES - len(retained))
                    except TimeoutError:
                        break
                    if not chunk:
                        break
                    retained.extend(chunk)
                banner = bytes(retained)
    except (OSError, RuntimeError, TimeoutError, ValueError):
        connected = False
        banner = b""

    output: dict[str, Any] = {
        "target": target,
        "addressFamily": address_family,
        "host": host,
        "transportProtocol": "tcp",
        "port": port,
        "protocolProfile": "tcp-passive-banner-v1",
        "connected": connected,
        "bannerBytes": len(banner),
        "bannerBase64": b64encode(banner).decode("ascii"),
        "bannerSha256": sha256(banner).hexdigest(),
    }
    if connected:
        service_name = _network_service_name(banner)
        if service_name is not None:
            output["serviceName"] = service_name
    else:
        output["error"] = "target-unavailable"
    return output


@dataclass(slots=True)
class _BoundedPipeCapture:
    limit: int
    retained: bytearray = field(default_factory=bytearray)
    truncated: bool = False
    error: BaseException | None = None

    def drain(self, stream: BinaryIO) -> None:
        try:
            while chunk := stream.read(_MCP_STREAM_CHUNK_BYTES):
                remaining = self.limit - len(self.retained)
                if remaining > 0:
                    self.retained.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.truncated = True
        except BaseException as exc:
            self.error = exc
        finally:
            stream.close()


@dataclass(slots=True)
class _BoundedStdinWrite:
    error: BaseException | None = None

    def write(self, stream: BinaryIO, payload: bytes) -> None:
        try:
            stream.write(payload)
            stream.flush()
        except BrokenPipeError:
            # The bridge's return code and stderr remain the authoritative failure.
            pass
        except BaseException as exc:
            self.error = exc
        finally:
            stream.close()


@dataclass(frozen=True, slots=True)
class _BoundedChildResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


def _kill_child_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill the bridge and any registered server descendants in its session."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError:
        if process.poll() is None:
            process.kill()


def _terminate_and_reap_mcp_child(process: subprocess.Popen[bytes]) -> None:
    """Terminate one MCP process group and put a hard bound on reaping it."""

    _kill_child_process_group(process)
    try:
        process.wait(timeout=_MCP_PROCESS_REAP_SECONDS)
    except subprocess.TimeoutExpired:
        # A platform-specific killpg failure may have left the direct child.
        # The child can exit between the timed wait and the fallback signal.
        # Treat that race as a successful kill and still perform the bounded reap.
        with suppress(ProcessLookupError):
            process.kill()
        process.wait(timeout=_MCP_PROCESS_REAP_SECONDS)


def _join_mcp_io_threads(
    process: subprocess.Popen[bytes],
    threads: tuple[Thread, ...],
) -> None:
    deadline = time.monotonic() + _MCP_READER_JOIN_SECONDS
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    if any(thread.is_alive() for thread in threads):
        # A descendant may have inherited a bridge pipe after its parent exited.
        _kill_child_process_group(process)
        deadline = time.monotonic() + _MCP_READER_JOIN_SECONDS
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
    if any(thread.is_alive() for thread in threads):
        raise RuntimeError("MCP bridge pipes did not close after process cleanup")


def _close_unstarted_child_streams(
    thread_streams: tuple[tuple[Thread, IO[bytes]], ...],
    started_threads: tuple[Thread, ...],
    all_streams: tuple[IO[bytes], ...],
) -> None:
    """Close pipes whose owning I/O thread never started."""

    started_stream_ids = {
        id(stream) for thread, stream in thread_streams if thread in started_threads
    }
    deferred_error: BaseException | None = None
    for stream in all_streams:
        if id(stream) in started_stream_ids:
            continue
        # Preserve the Thread.start/process failure as the authoritative
        # error while still attempting every remaining pipe.
        try:
            stream.close()
        except BaseException as exc:
            deferred_error = deferred_error or exc
    if deferred_error is not None:
        raise deferred_error


def _cleanup_failed_mcp_child(
    process: subprocess.Popen[bytes],
    thread_streams: tuple[tuple[Thread, IO[bytes]], ...],
    started_threads: tuple[Thread, ...],
    all_streams: tuple[IO[bytes], ...],
) -> tuple[bool, BaseException | None]:
    """Attempt every cleanup stage and classify failures without short-circuiting."""

    cleanup_failed = False
    cleanup_interrupt: BaseException | None = None
    operations: tuple[Callable[[], None], ...] = (
        lambda: _terminate_and_reap_mcp_child(process),
        lambda: _close_unstarted_child_streams(
            thread_streams,
            started_threads,
            all_streams,
        ),
        lambda: _join_mcp_io_threads(process, started_threads),
    )
    for operation in operations:
        try:
            operation()
        except BaseException as exc:
            if isinstance(exc, Exception):
                cleanup_failed = True
            else:
                cleanup_interrupt = cleanup_interrupt or exc
    return cleanup_failed, cleanup_interrupt


def _run_bounded_child(
    command: list[str],
    *,
    input_bytes: bytes,
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
) -> _BoundedChildResult:
    """Run one child with simultaneous drains and bounded retained transcripts."""

    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        existing_streams = tuple(
            stream
            for stream in (process.stdin, process.stdout, process.stderr)
            if stream is not None
        )
        try:
            _terminate_and_reap_mcp_child(process)
        finally:
            for stream in existing_streams:
                with suppress(Exception):
                    stream.close()
        raise RuntimeError("MCP bridge pipes were not created")
    stdout = _BoundedPipeCapture(limit=stdout_limit)
    stderr = _BoundedPipeCapture(limit=stderr_limit)
    stdin = _BoundedStdinWrite()
    thread_specs = (
        (stdout.drain, (process.stdout,), process.stdout),
        (stderr.drain, (process.stderr,), process.stderr),
        (stdin.write, (process.stdin, input_bytes), process.stdin),
    )
    all_streams = (process.stdout, process.stderr, process.stdin)
    thread_streams: list[tuple[Thread, IO[bytes]]] = []
    started_threads: list[Thread] = []
    try:
        for target, arguments, stream in thread_specs:
            thread_streams.append((Thread(target=target, args=arguments, daemon=True), stream))
        threads = tuple(thread for thread, _stream in thread_streams)
        for thread in threads:
            thread.start()
            started_threads.append(thread)
        returncode = process.wait(timeout=timeout_seconds)
    except BaseException as primary_error:
        started = tuple(started_threads)
        cleanup_failed, cleanup_interrupt = _cleanup_failed_mcp_child(
            process,
            tuple(thread_streams),
            started,
            all_streams,
        )
        if cleanup_interrupt is not None:
            raise cleanup_interrupt from primary_error
        if cleanup_failed:
            primary_error.add_note("MCP child cleanup was incomplete")
        raise
    _join_mcp_io_threads(process, threads)
    for stream_name, error in (
        ("stdin", stdin.error),
        ("stdout", stdout.error),
        ("stderr", stderr.error),
    ):
        if error is not None:
            raise RuntimeError(f"MCP bridge {stream_name} pipe failed") from error
    return _BoundedChildResult(
        returncode=returncode,
        stdout=bytes(stdout.retained),
        stderr=bytes(stderr.retained),
        stdout_truncated=stdout.truncated,
        stderr_truncated=stderr.truncated,
    )


def _run_mcp_bridge(payload: dict[str, Any]) -> dict[str, Any]:
    completed = _run_bounded_child(
        ["python", "/app/mcp_bridge.py"],
        input_bytes=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        timeout_seconds=20,
        stdout_limit=MAX_MCP_RESPONSE_BYTES,
        stderr_limit=MAX_MCP_STDERR_BYTES,
    )
    if completed.stdout_truncated:
        raise ValueError("MCP bridge output exceeded byte limit")
    if completed.stderr_truncated:
        raise ValueError("MCP bridge stderr exceeded byte limit")
    try:
        stdout = completed.stdout.decode("utf-8")
        completed.stderr.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("MCP bridge output is not valid UTF-8") from exc
    if completed.returncode != 0:
        raise RuntimeError(f"MCP bridge exited with code {completed.returncode}")
    return _strict_json_object(stdout, label="MCP bridge output")


def mcp_call(payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) != {"serverId", "toolName", "arguments"}:
        raise ValueError("MCP call input fields do not match the registered envelope")
    return _run_mcp_bridge(payload)


def mcp_discover(payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) != {"serverId"}:
        raise ValueError("MCP discovery input must contain only a registered server ID")
    return _run_mcp_bridge(payload)


def _isolation_action(payload: dict[str, Any]) -> dict[str, Any]:
    if payload:
        raise ValueError("isolation check does not accept arguments")
    return isolation_check()


def _sleep_action(payload: dict[str, Any]) -> dict[str, Any]:
    seconds = payload.get("seconds", 2)
    if isinstance(seconds, bool) or not isinstance(seconds, int | float):
        raise TypeError("sleep duration must be a number")
    if not 0 <= seconds <= 30:
        raise ValueError("sleep duration must be between 0 and 30 seconds")
    time.sleep(seconds)
    return {"slept": True, "seconds": seconds}


_UNPRIVILEGED_ACTIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "mock-agent-probe": mock_agent_probe,
    "isolation-check": _isolation_action,
    "sleep-check": _sleep_action,
    "http-get": http_get,
    "network-service-identify": network_service_identify,
    "ai-chat-probe": ai_chat_probe,
    "bug-bounty-sqli-probe": bug_bounty_sqli_probe,
    "ctf-web-backup-probe": ctf_web_backup_probe,
    "ctf-crypto-single-byte-xor": ctf_crypto_single_byte_xor,
    "direct-network-check": direct_network_check,
    "mcp-call": mcp_call,
    "mcp-discover": mcp_discover,
}
_PROVIDER_ACTION = "openai-chat-completion"


def _dispatch_action(
    action: str,
    payload: dict[str, Any],
    secrets: dict[str, str],
) -> dict[str, Any]:
    if action == _PROVIDER_ACTION:
        if set(secrets) != {"provider-api-key"}:
            raise ValueError("provider action requires exactly one API key binding")
        return openai_chat_completion(payload, secrets)
    if secrets:
        raise ValueError("worker action does not accept secret bindings")
    return _UNPRIVILEGED_ACTIONS[action](payload)


def _supported_action(action: str) -> bool:
    return action == _PROVIDER_ACTION or action in _UNPRIVILEGED_ACTIONS


def main() -> int:
    if len(sys.argv) != 2:
        print("unsupported worker action", file=sys.stderr)
        return 64
    action = sys.argv[1]
    if not _supported_action(action):
        print("unsupported worker action", file=sys.stderr)
        return 64
    try:
        payload, secrets = _unwrap_worker_envelope(_read_worker_input(sys.stdin))
        result = _dispatch_action(action, payload, secrets)
    except (
        KeyError,
        TypeError,
        AttributeError,
        ValueError,
    ):
        print("invalid worker input or response", file=sys.stderr)
        return 65
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        print("worker action failed", file=sys.stderr)
        return 70
    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
