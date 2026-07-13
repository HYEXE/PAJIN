"""Minimal PAJIN development worker image entrypoint."""

import json
import os
import socket
import subprocess
import sys
import time
from hashlib import sha256
from hmac import compare_digest
from re import fullmatch
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

MAX_AI_RESPONSE_BYTES = 65_536
MAX_BUG_BOUNTY_RESPONSE_BYTES = 32_768
MAX_CTF_WEB_RESPONSE_BYTES = 16_384
MAX_CTF_CRYPTO_ARTIFACT_BYTES = 4_096


def mock_agent_probe(payload: dict[str, Any]) -> dict[str, Any]:
    simulation = payload.get("simulation", {})
    vulnerable = bool(simulation.get("unauthorizedToolCall", False))
    return {
        "vulnerable": vulnerable,
        "observation": (
            "target accepted an untrusted instruction and invoked a protected tool"
            if vulnerable
            else "target rejected the untrusted instruction"
        ),
        "target": payload["target"],
        "networkPerformed": False,
    }


def _read_cgroup(name: str) -> str | None:
    path = f"/sys/fs/cgroup/{name}"
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def isolation_check() -> dict[str, Any]:
    network_blocked = False
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=0.25):
            pass
    except OSError:
        network_blocked = True

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
        "rootReadOnly": bool(os.statvfs("/").f_flag & os.ST_RDONLY),
        "workspaceWritable": workspace_writable,
        "capabilitiesDropped": int(status.get("CapEff", "1"), 16) == 0,
        "noNewPrivileges": status.get("NoNewPrivs") == "1",
        "memoryMax": _read_cgroup("memory.max"),
        "pidsMax": _read_cgroup("pids.max"),
        "cpuMax": _read_cgroup("cpu.max"),
    }


def http_get(payload: dict[str, Any]) -> dict[str, Any]:
    target = str(payload["target"])
    request = Request(target, method="GET", headers={"User-Agent": "PAJIN-Worker/0.1"})
    try:
        with urlopen(request, timeout=10) as response:
            body = response.read(4_096)
            return {
                "target": target,
                "status": response.status,
                "contentType": response.headers.get("Content-Type"),
                "bodyPreview": body.decode("utf-8", errors="replace"),
            }
    except HTTPError as exc:
        body = exc.read(4_096)
        return {
            "target": target,
            "status": exc.code,
            "contentType": exc.headers.get("Content-Type"),
            "bodyPreview": body.decode("utf-8", errors="replace"),
        }
    except URLError as exc:
        return {"target": target, "status": 0, "error": str(exc.reason)}


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
        with urlopen(request, timeout=10) as response:
            body = response.read(MAX_BUG_BOUNTY_RESPONSE_BYTES + 1)
            status = response.status
    except HTTPError as exc:
        body = exc.read(MAX_BUG_BOUNTY_RESPONSE_BYTES + 1)
        status = exc.code
    except URLError as exc:
        raise ValueError(f"Bug Bounty target request failed: {exc.reason}") from exc
    if len(body) > MAX_BUG_BOUNTY_RESPONSE_BYTES:
        raise ValueError("Bug Bounty target response exceeded byte limit")
    response_data = json.loads(body)
    if not isinstance(response_data, dict):
        raise TypeError("Bug Bounty target response must be an object")
    record_count = response_data.get("recordCount")
    synthetic = response_data.get("synthetic")
    if not isinstance(record_count, int) or isinstance(record_count, bool):
        raise TypeError("Bug Bounty target response requires integer recordCount")
    if not isinstance(synthetic, bool):
        raise TypeError("Bug Bounty target response requires boolean synthetic")
    return {
        "name": name,
        "status": status,
        "recordCount": record_count,
        "synthetic": synthetic,
    }


def bug_bounty_sqli_probe(payload: dict[str, Any]) -> dict[str, Any]:
    target = str(payload["target"])
    scenario_id = str(payload["scenarioId"])
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


def ctf_web_backup_probe(payload: dict[str, Any]) -> dict[str, Any]:
    target = str(payload["target"])
    challenge_id = str(payload["challengeId"])
    scenario_id = str(payload["scenarioId"])
    if scenario_id != "web.exposed-backup-config":
        raise ValueError("unsupported CTF Web scenario")
    parsed = urlsplit(target)
    if parsed.scheme != "http" or parsed.hostname != "host.docker.internal" or parsed.port != 8780:
        raise ValueError("CTF Web target must use the fixed local lab authority")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("CTF Web target authority, query, or fragment is invalid")
    if parsed.path != "/backup/config.json.bak":
        raise ValueError("CTF Web target must use the fixed backup path")

    request = Request(
        target,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "PAJIN-CTF-Web-Probe/1.0"},
    )
    try:
        with urlopen(request, timeout=10) as response:
            body = response.read(MAX_CTF_WEB_RESPONSE_BYTES + 1)
            status = response.status
    except HTTPError as exc:
        body = exc.read(MAX_CTF_WEB_RESPONSE_BYTES + 1)
        status = exc.code
    except URLError as exc:
        raise ValueError(f"CTF Web target request failed: {exc.reason}") from exc
    if len(body) > MAX_CTF_WEB_RESPONSE_BYTES:
        raise ValueError("CTF Web target response exceeded byte limit")
    response_data = json.loads(body)
    if not isinstance(response_data, dict):
        raise TypeError("CTF Web target response must be an object")
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
    return {
        "target": target,
        "challengeId": challenge_id,
        "scenarioId": scenario_id,
        "status": status,
        "discovered": status == 200 and candidate is not None,
        "candidateFlag": candidate,
        "bodySha256": sha256(body).hexdigest(),
        "synthetic": True,
        "networkPerformed": True,
    }


def ctf_crypto_single_byte_xor(payload: dict[str, Any]) -> dict[str, Any]:
    target = str(payload["target"])
    challenge_id = str(payload["challengeId"])
    scenario_id = str(payload["scenarioId"])
    artifact_sha256 = str(payload["artifactSha256"])
    ciphertext_hex = str(payload["ciphertextHex"])
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

    matches: list[tuple[int, str]] = []
    for key in range(256):
        plaintext_bytes = bytes(value ^ key for value in ciphertext)
        try:
            plaintext = plaintext_bytes.decode("ascii")
        except UnicodeDecodeError:
            continue
        if fullmatch(r"PAJIN\{[A-Za-z0-9_-]{1,128}\}", plaintext):
            matches.append((key, plaintext))
    if len(matches) > 1:
        raise ValueError("CTF Crypto analysis produced ambiguous flag candidates")
    key, candidate = matches[0] if matches else (None, None)
    return {
        "target": target,
        "challengeId": challenge_id,
        "scenarioId": scenario_id,
        "artifactSha256": artifact_sha256,
        "solved": candidate is not None,
        "candidateFlag": candidate,
        "key": key,
        "attemptedKeys": 256,
        "synthetic": True,
        "networkPerformed": False,
    }


def _post_ai_turn(target: str, payload: dict[str, Any]) -> tuple[dict[str, Any], float]:
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("AI target must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("AI target URL credentials are forbidden")
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(
        target,
        data=encoded,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "PAJIN-AI-Probe/1.0",
        },
    )
    started = time.perf_counter()
    try:
        with urlopen(request, timeout=10) as response:
            body = response.read(MAX_AI_RESPONSE_BYTES + 1)
            status = response.status
    except HTTPError as exc:
        detail = exc.read(4_096).decode("utf-8", errors="replace")
        raise ValueError(f"AI target returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise ValueError(f"AI target request failed: {exc.reason}") from exc
    if len(body) > MAX_AI_RESPONSE_BYTES:
        raise ValueError("AI target response exceeded byte limit")
    if not 200 <= status < 300:
        raise ValueError(f"AI target returned unexpected HTTP {status}")
    result = json.loads(body)
    if not isinstance(result, dict):
        raise TypeError("AI target response must be an object")
    message = result.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise TypeError("AI target response requires message.content")
    return result, time.perf_counter() - started


def _probe_check_matches(check: dict[str, Any], turns: list[dict[str, Any]]) -> bool:
    turn_index = int(check["turn"])
    if not 0 <= turn_index < len(turns):
        raise ValueError("probe check references a missing turn")
    response = turns[turn_index]["response"]
    content = response["message"]["content"]
    if not isinstance(content, str):
        raise TypeError("AI response content must be a string")
    value = str(check["value"])
    kind = str(check["kind"])
    if kind == "response-contains":
        return value in content
    if kind == "response-excludes":
        return value not in content
    raise ValueError(f"unsupported probe check kind: {kind}")


def ai_chat_probe(payload: dict[str, Any]) -> dict[str, Any]:
    target = str(payload["target"])
    probe = payload["probe"]
    if not isinstance(probe, dict):
        raise TypeError("probe must be an object")
    scenario_id = str(probe["scenario_id"])
    threat_class = str(probe["threat_class"])
    session_id = str(probe["session_id"])
    purpose = str(probe.get("purpose", "attack"))
    if purpose not in {"attack", "regression"}:
        raise ValueError("probe purpose must be attack or regression")
    turns = probe["turns"]
    checks = probe["checks"]
    if not isinstance(turns, list) or not 1 <= len(turns) <= 20:
        raise ValueError("probe turns must contain between 1 and 20 items")
    if not isinstance(checks, list) or not 1 <= len(checks) <= 20:
        raise ValueError("probe checks must contain between 1 and 20 items")

    turn_records: list[dict[str, Any]] = []
    response_latencies: list[float] = []
    for index, turn in enumerate(turns):
        if not isinstance(turn, dict) or not isinstance(turn.get("messages"), list):
            raise TypeError("each probe turn requires messages")
        request_payload = {
            "sessionId": session_id,
            "messages": turn["messages"],
            "metadata": {"scenarioId": scenario_id, "turn": index},
        }
        response, response_latency = _post_ai_turn(target, request_payload)
        response_latencies.append(response_latency)
        turn_records.append(
            {
                "index": index,
                "name": str(turn.get("name", f"turn-{index}")),
                "request": request_payload,
                "response": response,
                "responseLatencySeconds": response_latency,
            }
        )

    check_records: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, dict):
            raise TypeError("each probe check must be an object")
        matched = _probe_check_matches(check, turn_records)
        check_records.append(
            {
                "checkId": str(check["check_id"]),
                "kind": str(check["kind"]),
                "turn": int(check["turn"]),
                "matched": matched,
                "sensitive": bool(check.get("sensitive", False)),
            }
        )
    checks_passed = all(check["matched"] for check in check_records)
    vulnerable = checks_passed if purpose == "attack" else False
    sensitive_exposures = sum(
        bool(check["matched"] and check["sensitive"]) for check in check_records
    )
    return {
        "target": target,
        "scenarioId": scenario_id,
        "threatClass": threat_class,
        "sessionId": session_id,
        "purpose": purpose,
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
        "regressionPassed": checks_passed if purpose == "regression" else None,
        "networkPerformed": True,
    }


def _normalize_provider_tool_call(raw: dict[str, Any]) -> dict[str, Any]:
    call_id = raw.get("id")
    function = raw.get("function")
    if not isinstance(call_id, str) or not isinstance(function, dict):
        raise TypeError("provider tool call requires id and function")
    name = function.get("name")
    arguments_json = function.get("arguments")
    if not isinstance(name, str) or not isinstance(arguments_json, str):
        raise TypeError("provider function call requires name and string arguments")
    arguments: dict[str, Any] | None = None
    arguments_valid = False
    try:
        parsed = json.loads(arguments_json)
        if isinstance(parsed, dict):
            arguments = parsed
            arguments_valid = True
    except json.JSONDecodeError:
        pass
    return {
        "call_id": call_id,
        "name": name,
        "arguments_json": arguments_json,
        "arguments": arguments,
        "arguments_valid": arguments_valid,
    }


def _provider_usage(raw: object) -> dict[str, int | None] | None:
    if not isinstance(raw, dict):
        return None
    fields = ("prompt_tokens", "completion_tokens", "total_tokens")
    return {field: int(raw[field]) if isinstance(raw.get(field), int) else None for field in fields}


def _normalize_nonstream_provider(
    payload: dict[str, Any],
    *,
    provider_id: str,
    target: str,
) -> dict[str, Any]:
    response_id = payload.get("id")
    model = payload.get("model")
    choices = payload.get("choices")
    if not isinstance(response_id, str) or not isinstance(model, str):
        raise TypeError("provider response requires id and model")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise TypeError("provider response requires at least one choice")
    choice = choices[0]
    message = choice.get("message")
    if not isinstance(message, dict):
        raise TypeError("provider choice requires a message")
    raw_tool_calls = message.get("tool_calls", [])
    if not isinstance(raw_tool_calls, list):
        raise TypeError("provider message tool_calls must be a list")
    content = message.get("content")
    refusal = message.get("refusal")
    if content is not None and not isinstance(content, str):
        raise TypeError("provider message content must be a string or null")
    if refusal is not None and not isinstance(refusal, str):
        raise TypeError("provider message refusal must be a string or null")
    return {
        "provider_id": provider_id,
        "response_id": response_id,
        "model": model,
        "content": content,
        "refusal": refusal,
        "finish_reason": (
            str(choice["finish_reason"]) if choice.get("finish_reason") is not None else None
        ),
        "tool_calls": [
            _normalize_provider_tool_call(item) for item in raw_tool_calls if isinstance(item, dict)
        ],
        "usage": _provider_usage(payload.get("usage")),
        "streamed": False,
        "chunks": 1,
        "target": target,
    }


def _normalize_stream_provider(
    response: Any,
    *,
    provider_id: str,
    target: str,
) -> dict[str, Any]:
    total_bytes = 0
    chunks = 0
    done = False
    response_id: str | None = None
    model: str | None = None
    content_parts: list[str] = []
    refusal_parts: list[str] = []
    finish_reason: str | None = None
    usage: dict[str, int | None] | None = None
    tool_calls: dict[int, dict[str, Any]] = {}
    for raw_line in response:
        total_bytes += len(raw_line)
        if total_bytes > 1_000_000:
            raise ValueError("provider SSE response exceeded byte limit")
        line = raw_line.decode("utf-8", errors="strict").strip()
        if not line or line.startswith(":") or not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            done = True
            break
        chunk = json.loads(data)
        if not isinstance(chunk, dict):
            raise TypeError("provider SSE chunk must be an object")
        chunks += 1
        if chunks > 10_000:
            raise ValueError("provider SSE response exceeded chunk limit")
        if isinstance(chunk.get("id"), str):
            response_id = chunk["id"]
        if isinstance(chunk.get("model"), str):
            model = chunk["model"]
        chunk_usage = _provider_usage(chunk.get("usage"))
        if chunk_usage is not None:
            usage = chunk_usage
        choices = chunk.get("choices")
        if not isinstance(choices, list) or not choices:
            continue
        choice = choices[0]
        if not isinstance(choice, dict):
            raise TypeError("provider SSE choice must be an object")
        if choice.get("finish_reason") is not None:
            finish_reason = str(choice["finish_reason"])
        delta = choice.get("delta")
        if not isinstance(delta, dict):
            continue
        if isinstance(delta.get("content"), str):
            content_parts.append(delta["content"])
        if isinstance(delta.get("refusal"), str):
            refusal_parts.append(delta["refusal"])
        raw_tool_calls = delta.get("tool_calls", [])
        if not isinstance(raw_tool_calls, list):
            raise TypeError("provider SSE tool_calls must be a list")
        for raw_call in raw_tool_calls:
            if not isinstance(raw_call, dict) or not isinstance(raw_call.get("index"), int):
                raise TypeError("provider SSE tool call requires an index")
            index = raw_call["index"]
            accumulated = tool_calls.setdefault(
                index,
                {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
            )
            if isinstance(raw_call.get("id"), str):
                accumulated["id"] = raw_call["id"]
            function = raw_call.get("function")
            if isinstance(function, dict):
                if isinstance(function.get("name"), str):
                    accumulated["function"]["name"] += function["name"]
                if isinstance(function.get("arguments"), str):
                    accumulated["function"]["arguments"] += function["arguments"]
    if not done:
        raise ValueError("provider SSE stream ended without [DONE]")
    if chunks < 1 or response_id is None or model is None:
        raise ValueError("provider SSE stream is missing identity chunks")
    return {
        "provider_id": provider_id,
        "response_id": response_id,
        "model": model,
        "content": "".join(content_parts) or None,
        "refusal": "".join(refusal_parts) or None,
        "finish_reason": finish_reason,
        "tool_calls": [
            _normalize_provider_tool_call(tool_calls[index]) for index in sorted(tool_calls)
        ],
        "usage": usage,
        "streamed": True,
        "chunks": chunks,
        "target": target,
    }


def openai_chat_completion(
    payload: dict[str, Any],
    secrets: dict[str, str],
) -> dict[str, Any]:
    credential = secrets.get("provider-api-key")
    if not credential:
        raise ValueError("provider API key binding is required")
    provider_id = str(payload["providerId"])
    target = str(payload["target"])
    provider_request = payload["request"]
    if not isinstance(provider_request, dict):
        raise TypeError("provider request must be an object")
    stream = provider_request.get("stream", False)
    if not isinstance(stream, bool):
        raise TypeError("provider stream must be boolean")
    encoded = json.dumps(provider_request, separators=(",", ":")).encode("utf-8")
    request = Request(
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
    try:
        with urlopen(request, timeout=30) as response:
            if stream:
                return _normalize_stream_provider(
                    response,
                    provider_id=provider_id,
                    target=target,
                )
            body = response.read(1_000_001)
    except HTTPError as exc:
        detail = exc.read(8_192).decode("utf-8", errors="replace")
        raise ValueError(f"provider returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise ValueError(f"provider request failed: {exc.reason}") from exc
    if len(body) > 1_000_000:
        raise ValueError("provider response exceeded byte limit")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise TypeError("provider response must be an object")
    return _normalize_nonstream_provider(
        parsed,
        provider_id=provider_id,
        target=target,
    )


def direct_network_check(payload: dict[str, Any]) -> dict[str, Any]:
    host = str(payload.get("host", "example.com"))
    port = int(payload.get("port", 80))
    try:
        with socket.create_connection((host, port), timeout=1):
            return {"directNetworkBlocked": False}
    except OSError:
        return {"directNetworkBlocked": True}


def mcp_call(payload: dict[str, Any]) -> dict[str, Any]:
    completed = subprocess.run(
        ["python", "/app/mcp_bridge.py"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, end="")
    if completed.returncode != 0:
        raise RuntimeError(f"MCP bridge exited with code {completed.returncode}")
    result = json.loads(completed.stdout)
    if not isinstance(result, dict):
        raise TypeError("MCP bridge output must be an object")
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print("unsupported worker action", file=sys.stderr)
        return 64
    try:
        action = sys.argv[1]
        wire_payload = json.load(sys.stdin)
        if not isinstance(wire_payload, dict):
            raise TypeError("worker input must be an object")
        secrets: dict[str, str] = {}
        if wire_payload.get("pajinEnvelopeVersion") == 1:
            payload = wire_payload.get("payload")
            raw_secrets = wire_payload.get("secrets")
            if not isinstance(payload, dict) or not isinstance(raw_secrets, dict):
                raise TypeError("worker secret envelope is malformed")
            if not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in raw_secrets.items()
            ):
                raise TypeError("worker secret bindings must contain strings")
            secrets = raw_secrets
        else:
            payload = wire_payload
        if action == "mock-agent-probe":
            if secrets:
                raise ValueError("worker action does not accept secret bindings")
            result = mock_agent_probe(payload)
        elif action == "isolation-check":
            if secrets:
                raise ValueError("worker action does not accept secret bindings")
            result = isolation_check()
        elif action == "sleep-check":
            if secrets:
                raise ValueError("worker action does not accept secret bindings")
            time.sleep(float(payload.get("seconds", 2)))
            result = {"slept": True}
        elif action == "http-get":
            if secrets:
                raise ValueError("worker action does not accept secret bindings")
            result = http_get(payload)
        elif action == "ai-chat-probe":
            if secrets:
                raise ValueError("worker action does not accept secret bindings")
            result = ai_chat_probe(payload)
        elif action == "bug-bounty-sqli-probe":
            if secrets:
                raise ValueError("worker action does not accept secret bindings")
            result = bug_bounty_sqli_probe(payload)
        elif action == "ctf-web-backup-probe":
            if secrets:
                raise ValueError("worker action does not accept secret bindings")
            result = ctf_web_backup_probe(payload)
        elif action == "ctf-crypto-single-byte-xor":
            if secrets:
                raise ValueError("worker action does not accept secret bindings")
            result = ctf_crypto_single_byte_xor(payload)
        elif action == "direct-network-check":
            if secrets:
                raise ValueError("worker action does not accept secret bindings")
            result = direct_network_check(payload)
        elif action == "mcp-call":
            if secrets:
                raise ValueError("worker action does not accept secret bindings")
            result = mcp_call(payload)
        elif action == "openai-chat-completion":
            if set(secrets) != {"provider-api-key"}:
                raise ValueError("provider action requires exactly one API key binding")
            result = openai_chat_completion(payload, secrets)
        else:
            print("unsupported worker action", file=sys.stderr)
            return 64
    except (
        json.JSONDecodeError,
        KeyError,
        TypeError,
        AttributeError,
        ValueError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"invalid worker input: {exc}", file=sys.stderr)
        return 65
    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
