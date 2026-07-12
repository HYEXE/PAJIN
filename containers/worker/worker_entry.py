"""Minimal PAJIN development worker image entrypoint."""

import json
import os
import socket
import subprocess
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


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
        payload = json.load(sys.stdin)
        if action == "mock-agent-probe":
            result = mock_agent_probe(payload)
        elif action == "isolation-check":
            result = isolation_check()
        elif action == "sleep-check":
            time.sleep(float(payload.get("seconds", 2)))
            result = {"slept": True}
        elif action == "http-get":
            result = http_get(payload)
        elif action == "direct-network-check":
            result = direct_network_check(payload)
        elif action == "mcp-call":
            result = mcp_call(payload)
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
